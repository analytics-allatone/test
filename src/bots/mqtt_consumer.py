import asyncio
import aiomqtt
import os 
import json
from dotenv import load_dotenv
from db.db import push_data_to_db , get_async_session
from sqlalchemy import select
from models.agent_model import Agents

load_dotenv()

# ⚠️ CONFIGURATION: Must match Step 2 parameters exactly
SERVER_IP = "80.225.239.163" 
MQTT_USER = "my_mqtt_user"
MQTT_PASS = "mqttpassword"
TOPIC = "agent/agent_events"


VALID_CATEGORIES = ["authentication" , "file" , "network" , "process" , "usb"]


BATCH_SIZE = 50




async def fetch_agents_map(machine_info):
    """Helper function to cleanly fetch agents without blocking the MQTT loop"""
    mapping = {}
    try:
        async with get_async_session() as db:
            curr_agent = await db.execute(select(Agents).where(Agents.agent_name == machine_info.get("agent_name")))
            curr_agent = curr_agent.scalars().first()
            if curr_agent:
                valid_cols = set(Agents.__table__.columns.keys())
                for k, v in machine_info.items():
                    if k != "agent_name" and k in valid_cols:
                        setattr(curr_agent, k, v)
                curr_agent.status = "active"

                await db.commit()
            result = await db.execute(select(Agents))
            all_agents = result.scalars().all()
            for ag in all_agents:
                mapping[ag.agent_name] = ag.id
    except Exception as e:
        print(f"❌ Error fetching agents map: {e}")
    return mapping


async def mqtt_background_consumer():
    master_dict = {}
    agents_map = {}
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

                    agent_name = machine_info.get("agent_name" , None)

                    category = event_data.get("category" , None)

                    if not agent_name or not category or category not in VALID_CATEGORIES:
                        continue

                    if agent_name not in agents_map:
                        print(f"🔍 New agent detected: {agent_name}. Refreshing cache...")
                        agents_map = await fetch_agents_map(machine_info)


                    if not master_dict.get(agent_name):
                        master_dict[agent_name] = {}
                        master_dict[agent_name]["meta_data"] = machine_info
                        master_dict[agent_name]["event_data"] = []
                    
                    master_dict[agent_name]["event_data"].append(event_data)
                    if len(master_dict[agent_name]["event_data"]) >= BATCH_SIZE:
                        await push_data_to_db(master_dict[agent_name] , agents_map)
                        master_dict[agent_name]["event_data"] = []




                    
        except aiomqtt.MqttError as error:
            print(f"⚠️ Network error: {error}. Reconnecting in 5 seconds...")
            await asyncio.sleep(5)