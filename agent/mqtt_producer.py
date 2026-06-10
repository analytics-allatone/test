import asyncio
import json
from datetime import datetime
import aiomqtt



class MQTTProducer:
    def __init__(self, server_ip, mqtt_user, mqtt_pass, mqtt_topic):
        self.server_ip = server_ip
        self.mqtt_user = mqtt_user 
        self.mqtt_pass = mqtt_pass
        self.mqtt_topic = mqtt_topic
        self._client = None  # Persistent client to avoid connecting on every single push

    def _default_serializer(self, obj):
        """Custom encoder for non-standard data types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            # 🌟 FIX: Convert raw bytes in your events (like hashes or IDs) to string!
            return obj.decode('utf-8', errors='ignore')
        raise TypeError(f"Type not serializable: {type(obj)}")

    async def push(self, event , machine_info = {}):
        """Pushes a single log item cleanly to the MQTT broker."""
        try:
            # 1. Nest the dictionary objects completely BEFORE converting to JSON string
            full_payload_dict = {
                "machine_info" : machine_info,
                "event": event
            }
            print(full_payload_dict)
            # 2. Serialize the combined dictionary using the custom handler
            json_string = json.dumps(full_payload_dict, default=self._default_serializer)
            
            # 3. Use an active connection if it exists, otherwise create a new context
            if self._client is None:
                self._client = aiomqtt.Client(
                    hostname=self.server_ip,
                    port=1883,
                    username=self.mqtt_user,
                    password=self.mqtt_pass
                )
                await self._client.__aenter__()

            # 4. Publish exactly once (NO while True loop here!)
            # aiomqtt accepts either raw strings or encoded bytes for the payload parameter
            await self._client.publish(self.mqtt_topic, payload=json_string)

        except aiomqtt.MqttError as error:
            print(f"⚠️ Error pushing to MQTT server: {error}")
            # Reset client reference on failure to force reconnection next cycle
            self._client = None
            raise error  # Let EventDispatcher's try-except block catch this and handle the sleep
            
        except TypeError as err:
            print(f"❌ Serialization Failure: {err}")
