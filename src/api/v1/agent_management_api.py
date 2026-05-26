from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status , Query
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import base64
from sqlalchemy import desc ,select, func

###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################
from db.db import  get_async_db
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.agent_management_schema import (
    AddAgentRequest , AddAgentResponse,

    GetAgentsResponse , AgentData, AgentStatusCount,
    AgentGroupCount , AgentOSCount,

    GetAgentDataResponse
)

from models.agent_model import Agents , AgentGroups
# from models.event_model import MachineLogs

from auth.jwt_auth import verify_token




agent_management_router = APIRouter()




@agent_management_router.post("/add-agent" , response_model = standard_success_response[AddAgentResponse] , status_code = 201)
async def getAgents(req: AddAgentRequest , db: AsyncSession = Depends(get_async_db)):
    # user:dict = Depends(verify_token)
    agent_name = req.agent_name.strip()
    result = await db.execute(select(Agents).where(Agents.agent_name == agent_name))
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=401, detail="Agent already exists with this name")
    
    new_agent = Agents(
       agent_name = agent_name
    )
    if req.group_id:
        new_agent.group_id = req.group_id
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)

    res_data = AddAgentResponse(id = new_agent.id , agent_name= new_agent.agent_name , group_id = new_agent.group_id)
    return standard_success_response(data = res_data , message = "Agent added successfully")





@agent_management_router.get("/get-agents" , response_model = standard_success_response[GetAgentsResponse] , status_code = 200)
async def getAgents(db: AsyncSession = Depends(get_async_db)):
    # user:dict = Depends(verify_token)
    
    agents_list = []
    group_dict = {}
    agent_group_count = {}
    agent_status_count = {}
    agent_os_count = {}

    agent_status_count["total"] = 0


    group_result = await db.execute(select(AgentGroups))
    existing_groups = group_result.scalars().all()
    group_dict = {g.id : g.group_name for g in existing_groups}

    result = await db.execute(select(Agents))
    existing_agents = result.scalars().all()


    for agent in existing_agents:
        g_name = group_dict.get(agent.group_id , None)
        if g_name:
            if agent_group_count.get(g_name):
                agent_group_count[g_name] +=1
            else:
                agent_group_count[g_name] = 1

        agent_os = agent.os
        agent_os = agent_os.lower() if agent_os else None
        if agent_os and agent_os_count.get(agent_os):
            agent_os_count[agent_os] +=1
        elif agent_os:
            agent_os_count[agent_os] = 1

        status = agent.status
        if status:
            if agent_status_count.get(status):
                agent_status_count[status] +=1
            else:
                agent_status_count[status] = 1
            
            agent_status_count["total"] +=1

        curr_agent = AgentData(
            id = agent.id,
            agent_name = agent.agent_name,
            mac_address = agent.mac_address, 
            host_name = agent.host_name,
            main_ip = agent.main_ip,
            all_ips = agent.all_ips,
            os = agent.os,
            release = agent.release,
            version = agent.version,
            machine_architecture = agent.machine_architecture,
            is_active = agent.is_active,
            status = agent.status,
            group_name = g_name

        ) 
        agents_list.append(curr_agent)
    agent_os_count = [AgentOSCount(os_name = k , os_count = v) for k , v in agent_os_count.items()]
    agent_group_count = [AgentGroupCount(group_name = k , group_count = v) for k , v in agent_group_count.items()]
    agent_status_count = AgentStatusCount(
        total = agent_status_count.get("total"),
        active = agent_status_count.get("active" , 0),
        disconnected = agent_status_count.get("disconnected" , 0),
        pending = agent_status_count.get("pending" , 0),
        never_connected = agent_status_count.get("never_connected" , 0),
    )
    res_data = GetAgentsResponse(
        agent_status_count = agent_status_count,
        agent_os_count = agent_os_count,
        agent_group_count = agent_group_count,
        agents = agents_list
    )
    
    return standard_success_response(data = res_data , message = "Agents Data Fetched successfully")








# @agent_management_router.get("/get-agent-data" , response_model = standard_success_response[GetAgentDataResponse] , status_code = 200)
# async def getAgents(agent_name:str ):
#     #  user:dict = Depends(verify_token)
#     agent_data = []
#     agent_name = agent_name.strip()
#     async with get_async_db(agent_name) as db:
#         print("sdfghjk")
#         result = await db.execute(select(MachineLogs).order_by(desc(MachineLogs.id)))
#         db_logs = result.mappings().all()
#         print("sdfghjk")

#         agent_data = [dict(row)["MachineLogs"].__dict__ for row in db_logs]
#         print("sdfghjk")
        
#         # Clean up internal SQLAlchemy state tracking keys if necessary
#         for d in agent_data:
#             d.pop('_sa_instance_state', None)
#         print("sdfghjk")

#     res_data = GetAgentDataResponse(agent_data = agent_data)
    
#     return standard_success_response(data = res_data , message = f"Agent {agent_name} Data Fetched successfully")



# @agent_management_router.get("/get-agent-data", response_model=standard_success_response[GetAgentDataResponse], status_code=200)
# async def getAgents(
#     agent_name: str,
#     page: int = Query(default=1, ge=1, description="Page number, starting from 1"),
#     db: AsyncSession = Depends(get_async_db)
# ):
#     agent_name = agent_name.strip()
#     limit = 100
#     offset = (page - 1) * limit

#     query = (
#         select(MachineLogs)
#         .order_by(desc(MachineLogs.id))
#         .limit(limit)
#         .offset(offset)
#     )
#     result = await db.execute(query)
#     db_logs = result.mappings().all()

#     # 3. Transform data efficiently
#     agent_data = []
#     for row in db_logs:
#         log_obj = row["MachineLogs"]
#         # Convert to dict and safely remove SQLAlchemy internal state
#         log_dict = {k: v for k, v in log_obj.__dict__.items() if k != '_sa_instance_state'}
#         agent_data.append(log_dict)

#     # 4. Construct response
#     res_data = GetAgentDataResponse(agent_data=agent_data)
    
#     return standard_success_response(
#         data=res_data, 
#         message=f"Agent {agent_name} Data Fetched successfully (Page {page})"
#     )