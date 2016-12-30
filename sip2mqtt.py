import sys
import signal
import logging
import threading
import time
import argparse
import pjsua as pj
import paho.mqtt.client as mqtt

def signal_handler(signal, frame):
    print 'Exiting...'
    print"-- Unregistering --"
    time.sleep(2)
    print "-- Destroying Libraries --"
    time.sleep(2)
    lib.destroy()
    sys.exit(0)

# Method to print Log of callback class
def log_cb(level, str, len):
    print(str),

# Callback for an established MQTT broker connection
def mqtt_connect(broker, userdata, flags, rc):
    logging.info("MQTT: Connected with the broker...")

class SMCallCallback(pj.CallCallback):

    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)

    def on_media_state(self):
        #this event never really happens as sip2mqtt is never the one to answer the call.
        logging.info( "SIP: ON MEDIA STATE " + self.call.info() )
        if self.call.info().media_state == pj.MediaState.ACTIVE:
            logging.info("SIP: Media is now active")
        else:
            logging.info( "SIP: Media is inactive")

    def on_state(self):
        logging.info( "SIP: ON STATE " + self.call )
        logging.info( str(self.call.dump_status()) )
        logging.info( "SIP: Call with" + self.call.info().remote_uri )
        logging.info( "is" + self.call.info().state_text )
        logging.info( "last code =" + str(self.call.info().last_code) )
        logging.info( "(" + self.call.info().last_reason + ")" )

        if self.call.info().state == pj.CallState.CONFIRMED:
            #this state never really happens as sip2mqtt is never the one to answer the call.
            logging.info( 'SIP: Current call is answered' )
            broker.publish(args.status_topic, payload="Call from " + call.info().remote_uri + " answered", qos=0, retain=True)

        elif self.call.info().state == pj.CallState.DISCONNECTED:
            logging.info( 'SIP: Current call has ended' )
            broker.publish(args.status_topic, payload="Call from " + call.info().remote_uri + " ended", qos=0, retain=True)

# Callback to receive events from account
class SMAccountCallback(pj.AccountCallback):

    def __init__(self, account=None):
        pj.AccountCallback.__init__(self, account)

    def on_reg_state(self):
        logging.info( "SIP: Registration complete, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")" )

    # Notification on incoming call
    def on_incoming_call(self, call):
        logging.info( "SIP: Incoming call from " + call.info().remote_uri )
        broker.publish(args.status_topic, payload="Incoming call from " + call.info().remote_uri, qos=1, retain=True)

def main(argv):
    global broker
    global pj
    global lib

    app_name="SIP2MQTT"

    parser = argparse.ArgumentParser(description='A SIP monitoring tool that publishes incoming calls with CallerID to an MQTT channel')
    requiredNamed = parser.add_argument_group('required named arguments')

    requiredNamed.add_argument("-a",    "--mqtt_address",   type=str, required=True, help="the MQTT broker address string")
    requiredNamed.add_argument("-t",    "--mqtt_port",      type=int, required=True, help="the MQTT broker port number")
    parser.add_argument(                "--mqtt_keepalive", type=int, required=False, help="the MQTT broker keep alive in seconds", default=60)
    parser.add_argument(                "--mqtt_protocol",  type=str, required=False, help="the MQTT broker protocol", default="MQTTv311", choices=['MQTTv31', 'MQTTv311'])
    requiredNamed.add_argument("-u",    "--mqtt_username",  type=str, required=True, help="the MQTT broker username")
    requiredNamed.add_argument("-p",    "--mqtt_password",  type=str, required=True, help="the MQTT broker password")
    parser.add_argument(                "--status_topic",   type=str, required=False, help="the MQTT broker topic", default="home/sip")

    parser.add_argument(                "--trans_conf_port",        type=int, required=False, help="the SIP transport port number", default=5060)
    parser.add_argument(                "--trans_conf_bound_addr",  type=str, required=False, help="the SIP transport address string", default="")

    requiredNamed.add_argument("-d",    "--sip_domain",     type=str, required=True, help="the SIP domain")
    requiredNamed.add_argument("-n",    "--sip_username",   type=str, required=True, help="the SIP username")
    requiredNamed.add_argument("-s",    "--sip_password",   type=str, required=True, help="the SIP password")
    parser.add_argument(                "--sip_display",    type=str, required=False, help="the SIP user display name", default=app_name)

    parser.add_argument(                "--log_level",      type=int, required=False, help="the application log level", default=3, choices=[0, 1, 2, 3])

    parser.add_argument("-v",           "--verbosity",      action="count", help="increase output verbosity", default=3)

    args = parser.parse_args()

    print args.mqtt_address

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
    logging.basicConfig(filename="sip2mqtt.log", format="%(asctime)s - %(levelname)s - %(message)s",
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

        # Start of the Main Class
        # Create library instance of Lib class
        lib = pj.Lib()

        ua = pj.UAConfig()
        ua.user_agent = app_name

        mc = pj.MediaConfig()
        mc.clock_rate = 8000

        lib.init(ua_cfg = ua, log_cfg = pj.LogConfig(level=args.verbosity, callback=log_cb), media_cfg=mc)
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
