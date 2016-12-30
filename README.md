# sip2mqtt
A SIP monitoring script that publishes incoming calls with CallerID to an MQTT channel

see also [pjsip-docker](https://github.com/MartyTremblay/pjsip-docker)

## usage

Allows the monitoring of SIP connections and publishes the CallerID payload to an MQTT channel. The script requires the following parametters:

```bash
-a MQTT_ADDRESS, --mqtt_address MQTT_ADDRESS
                    the MQTT broker address string
-t MQTT_PORT,    --mqtt_port MQTT_PORT
                    the MQTT broker port number
-u MQTT_USERNAME, --mqtt_username MQTT_USERNAME
                    the MQTT broker username
-p MQTT_PASSWORD, --mqtt_password MQTT_PASSWORD
                    the MQTT broker password
-d SIP_DOMAIN,    --sip_domain SIP_DOMAIN
                    the SIP domain
-n SIP_USERNAME,  --sip_username SIP_USERNAME
                    the SIP username
-s SIP_PASSWORD,  --sip_password SIP_PASSWORD
                    the SIP password
```                    
Example:
```bash
python /opt/sip2mqtt/sip2mqtt.py -t16491 -afoo.cloudmqtt.com -uSip2Mqtt -pSECRET -dfoo.voip.ms -nSUB_DID -sSECRET -vvv
```                   
More optional parametters can be viewed by running python sip2mqtt.py -h
