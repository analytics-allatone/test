from pydantic import BaseModel



class AgentData(BaseModel):
    id : int
    agent_name : str
    mac_address : str
    host_name : str
    main_ip : str

    all_ips : list
    system : str
    release : str
    version : str
    machine_architecture : str

    is_active : bool
    
class GetAgentsResponse(BaseModel):
    agents : list[AgentData]




class GetAgentDataResponse(BaseModel):
    agent_data:list
    