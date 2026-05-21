import asyncio
import aiomqtt
import os 
import json
from dotenv import load_dotenv
from db.db import push_data_to_db

load_dotenv()

# ⚠️ CONFIGURATION: Must match Step 2 parameters exactly
SERVER_IP = "80.225.239.163" 
MQTT_USER = "my_mqtt_user"
MQTT_PASS = "mqttpassword"
TOPIC = "agent/events"


BATCH_SIZE = 100
async def mqtt_background_consumer():
    master_dict = {}
    while True:
        try:
            async with aiomqtt.Client(
                hostname=SERVER_IP,
                port=1883,
                username=MQTT_USER,
                password=MQTT_PASS
            ) as client:
                await client.subscribe(TOPIC)
                print(f" Consumer connected to and  Listening to: {TOPIC}")
                
                async for message in client.messages:
                    data_string = message.payload.decode('utf-8')

                    data_dict = json.loads(data_string)
                        
                    machine_info = data_dict.get("machine_info", {})
                    event_data = data_dict.get("event", {})

                    agent_name = machine_info.get("agent_name")
                    if not agent_name:
                        continue

                    if not master_dict.get("agent_name"):
                        master_dict["agent_name"] = {}
                        master_dict["agent_name"]["meta_data"] = machine_info
                        master_dict["agent_name"]["log_data"] = []
                    
                    master_dict["agent_name"]["log_data"].append(event_data)

                    if len(master_dict["agent_name"]["log_data"]) >= BATCH_SIZE:
                        await push_data_to_db(master_dict["agent_name"])
                        master_dict["agent_name"]["log_data"] = []




                    
        except aiomqtt.MqttError as error:
            print(f"⚠️ Network error: {error}. Reconnecting in 5 seconds...")
            await asyncio.sleep(5)