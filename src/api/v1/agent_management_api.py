from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import base64
from sqlalchemy import desc

###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################
from db.db import  get_async_db
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.agent_management_schema import (
    GetAgentsResponse , AgentData,
    GetAgentDataResponse
)

from models.master_model import User , AgentDBData
from models.data_log_model import MachineLogs

from auth.jwt_auth import verify_token




agent_management_router = APIRouter()

@agent_management_router.get("/get-agents" , response_model = standard_success_response[GetAgentsResponse] , status_code = 200)
async def getAgents():
    # user:dict = Depends(verify_token)
    
    agents_list = []
    async with get_async_db("master_database") as db:
        result = await db.execute(select(AgentDBData))
        existing_agents = result.scalars().all()

        for agent in existing_agents:
            curr_agent = AgentData(
                id = agent.id,
                agent_name = agent.agent_name,
                mac_address = agent.mac_address, 
                host_name = agent.host_name,
                main_ip = agent.main_ip,
                all_ips = agent.all_ips,
                system = agent.system,
                release = agent.release,
                version = agent.version,
                machine_architecture = agent.machine_architecture,
                is_active = agent.is_active

            )
            agents_list.append(curr_agent)
    res_data = GetAgentsResponse(agents = agents_list)
    
    return standard_success_response(data = res_data , message = "Agents Data Fetched successfully")








@agent_management_router.get("/get-agent-data" , response_model = standard_success_response[GetAgentDataResponse] , status_code = 200)
async def getAgents(agent_name:str ):
    #  user:dict = Depends(verify_token)
    agent_data = []
    agent_name = agent_name.strip()
    async with get_async_db(agent_name) as db:
        print("sdfghjk")
        result = await db.execute(select(MachineLogs).order_by(desc(MachineLogs.id)))
        db_logs = result.mappings().all()
        print("sdfghjk")

        agent_data = [dict(row)["MachineLogs"].__dict__ for row in db_logs]
        print("sdfghjk")
        
        # Clean up internal SQLAlchemy state tracking keys if necessary
        for d in agent_data:
            d.pop('_sa_instance_state', None)
        print("sdfghjk")

    res_data = GetAgentDataResponse(agent_data = agent_data)
    
    return standard_success_response(data = res_data , message = f"Agent {agent_name} Data Fetched successfully")