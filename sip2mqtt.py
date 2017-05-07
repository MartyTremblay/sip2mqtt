import sys
import os as os
import signal
import logging
import threading
import time
import re
import argparse
import json
import pjsua as pj
import paho.mqtt.client as mqtt

global args

def extract_caller_id(url):
    m = re.match(r"\"(.*)\"", url)
    return m.group(1)

def signal_handler(signal, frame):
    logging.info( 'Exiting...' )
    logging.info( '-- Unregistering --' )
    time.sleep(2)
    logging.info( '-- Destroying Libraries --' )
    time.sleep(2)
    lib.destroy()
    sys.exit(0)

# Method to print Log of callback class
def log_cb(level, str, len):
    logging.debug("SIP debug: " + str),

# Callback for an established MQTT broker connection
def mqtt_connect(broker, userdata, flags, rc):
    logging.info("MQTT: Connected with the broker...")

# Callback to receive events from account
class SMAccountCallback(pj.AccountCallback):
    global args

    def __init__(self, account=None):
        pj.AccountCallback.__init__(self, account)
        self.args = args

    def on_reg_state(self):
        logging.info( "SIP: Registration complete, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")" )

    def on_incoming_call(self, call):
        # Unless this callback is implemented, the default behavior is to reject the call with default status code.
        logging.info( "SIP: Incoming call from " + extract_caller_id( call.info().remote_uri ) )
        broker.publish(args.status_topic, payload="{\"verb\": \"incoming\", \"caller\":\"" + extract_caller_id( call.info().remote_uri ) + "\", \"uri\":" + json.dumps(call.info().remote_uri) + "}", qos=0, retain=True)

        current_call = call
        call_cb = SMCallCallback(current_call)
        current_call.set_callback(call_cb)

    def on_pager(self, from_uri, contact, mime_type, body):
        logging.info( "SIP: Incoming SMS from " + from_uri )
        broker.publish(args.status_topic, payload="{\"verb\": \"sms\", \"caller\":\"" + from_uri + "\", \"body\":" + json.dumps(body) + "}", qos=0, retain=True)


class SMCallCallback(pj.CallCallback):
    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)
        self.args = args

    # Notification when call state has changed
    def on_state(self):
        logging.info( 'SIP: Call state is: ' +  self.call.info().state_text )
        if self.call.info().state == pj.CallState.CONFIRMED:
            logging.info( 'SIP: Current call is answered' )
            broker.publish(args.status_topic, payload="{\"verb\": \"answered\", \"caller\":\"" + extract_caller_id( self.call.info().remote_uri ) + "\", \"uri\":" + json.dumps(self.call.info().remote_uri) + "}", qos=0, retain=True)
        elif self.call.info().state == pj.CallState.DISCONNECTED:
            logging.info( 'SIP: Current call has ended' )
            broker.publish(args.status_topic, payload="{\"verb\": \"disconnected\", \"caller\":\"\", \"uri\":\"\"}", qos=0, retain=True)

def main(argv):
    global broker
    global pj
    global lib
    global args

    app_name="SIP2MQTT"

    parser = argparse.ArgumentParser(description='A SIP monitoring tool that publishes incoming calls with CallerID to an MQTT channel')
    requiredNamed = parser.add_argument_group('required named arguments')

    requiredNamed.add_argument("-a",    "--mqtt_address",   type=str, required=True, help="the MQTT broker address string", default=os.environ.get('MQTT_ADDRESS', None))
    requiredNamed.add_argument("-t",    "--mqtt_port",      type=int, required=True, help="the MQTT broker port number", default=os.environ.get('MQTT_PORT', None))
    parser.add_argument(                "--mqtt_keepalive", type=int, required=False, help="the MQTT broker keep alive in seconds", default=60)
    parser.add_argument(                "--mqtt_protocol",  type=str, required=False, help="the MQTT broker protocol", default="MQTTv311", choices=['MQTTv31', 'MQTTv311'])
    requiredNamed.add_argument("-u",    "--mqtt_username",  type=str, required=True, help="the MQTT broker username", default=os.environ.get('MQTT_USERNAME', None))
    requiredNamed.add_argument("-p",    "--mqtt_password",  type=str, required=False, help="the MQTT broker password", default=os.environ.get('MQTT_PASSWORD', None))
    parser.add_argument(                "--status_topic",   type=str, required=False, help="the MQTT broker topic", default=os.environ.get('URL', "home/sip"))

    parser.add_argument(                "--trans_conf_port",        type=int, required=False, help="the SIP transport port number", default=os.environ.get('TRANS_CONF_PORT', 5060))
    parser.add_argument(                "--trans_conf_bound_addr",  type=str, required=False, help="the SIP transport address string", default=os.environ.get('TRANS_CONF_BOUND_ADDR', ""))

    requiredNamed.add_argument("-d",    "--sip_domain",     type=str, required=True, help="the SIP domain", default=os.environ.get('SIP_DOMAIN', None))
    requiredNamed.add_argument("-n",    "--sip_username",   type=str, required=True, help="the SIP username", default=os.environ.get('SIP_USERNAME', None))
    requiredNamed.add_argument("-s",    "--sip_password",   type=str, required=False, help="the SIP password", default=os.environ.get('SIP_PASSWORD', None))
    parser.add_argument(                "--sip_display",    type=str, required=False, help="the SIP user display name", default=app_name)

    parser.add_argument(                "--log_level",      type=int, required=False, help="the application log level", default=3, choices=[0, 1, 2, 3])

    parser.add_argument("-v",           "--verbosity",      action="count", help="increase output verbosity", default=3)

    args = parser.parse_args()

    log_level = logging.INFO #Deault logging level
    if args.verbosity == 1:
        log_level = logging.ERROR
    elif args.verbosity == 2:
        log_level = logging.WARN
    elif args.verbosity == 3:
        log_level = logging.INFO
    elif args.verbosity >= 4:
        log_level = logging.DEBUG

    # Configure logging
    # logging.basicConfig(filename="sip2mqtt.log", format="%(asctime)s - %(levelname)s - %(message)s",
    #                     datefmt="%m/%d/%Y %I:%M:%S %p", level=log_level)
    root = logging.getLogger()
    root.setLevel(log_level)

#    ch = logging.StreamHandler(sys.stdout)
#    ch.setLevel(log_level)
#    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#    ch.setFormatter(formatter)
#    root.addHandler(ch)
    # A more docker-friendly approach is to output to stdout
    logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%m/%d/%Y %I:%M:%S %p", level=log_level)

    # Log startup messages and our configuration parameters
    logging.info("------------------------")
    logging.info("Starting up...")
    logging.info("--- MQTT Broker Configuration ---")
    logging.info("Address: " + args.mqtt_address)
    logging.info("Port: " + str(args.mqtt_port))
    logging.info("Protocol: " + args.mqtt_protocol)
    logging.info("Username: " + args.mqtt_username)
    logging.info("Keepalive Interval: " + str(args.mqtt_keepalive))
    logging.info("Status Topic: " + args.status_topic)
    logging.info("--- SIP Configuration ---")
    logging.info("Domain: " + args.sip_domain)
    logging.info("Username: " + args.sip_username)
    logging.info("DisplayName: " + args.sip_display)

    try:
        # Handle mqtt connection and callbacks
        broker = mqtt.Client(client_id="", clean_session=True, userdata=None, protocol=eval("mqtt." + args.mqtt_protocol))
        broker.username_pw_set(args.mqtt_username, password=args.mqtt_password)
        broker.on_connect = mqtt_connect
        #broker.on_message = mqtt_message #don't need this callback for now
        broker.connect(args.mqtt_address, args.mqtt_port, args.mqtt_keepalive)

        # Create library instance of Lib class
        lib = pj.Lib()

        ua = pj.UAConfig()
        ua.user_agent = app_name

        mc = pj.MediaConfig()
        mc.clock_rate = 8000

        lib.init(ua_cfg = ua, log_cfg = pj.LogConfig(level=args.verbosity, callback=None), media_cfg=mc)
        lib.create_transport(pj.TransportType.UDP, pj.TransportConfig(args.trans_conf_port))
        lib.set_null_snd_dev()
        lib.start()

        acc_cfg = pj.AccountConfig()
        acc_cfg.id = "sip:" + args.sip_username + "@" + args.sip_domain
        acc_cfg.reg_uri = "sip:" + args.sip_domain
        acc_cfg.auth_cred = [ pj.AuthCred(args.sip_domain, args.sip_username, args.sip_password) ]
        acc_cfg.allow_contact_rewrite = False

        acc = lib.create_account(acc_cfg)
        acc_cb = SMAccountCallback(acc)
        acc.set_callback(acc_cb)

        logging.info( "-- Registration Complete --" )
        logging.info( 'SIP: Status = ' + str(acc.info().reg_status) + ' (' + acc.info().reg_reason + ')' )

    except pj.Error, e:
        logging.critical( ("Exception: " + str(e)) )
        lib.destroy()
        sys.exit(1)

    # Main work loop
    try:
        rc = broker.loop_start()
        if rc:
            logging.warn( "Warning: " + str(rc) )

        signal.signal(signal.SIGINT, signal_handler)
        while True:
            time.sleep(1)
        broker.loop_stop()

    except Exception, ex:
        logging.critical("Exception: " + str(ex))
        lib.destroy()
        sys.exit(1)

# Get things started
if __name__ == '__main__':
    main(sys.argv[1:])
