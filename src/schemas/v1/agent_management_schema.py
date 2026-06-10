from pydantic import BaseModel
from typing import Optional


class AddAgentRequest(BaseModel):
    agent_name : str
    group_id : Optional[int] = None


class AddAgentResponse(BaseModel):
    id : int
    agent_name : str
    group_id: Optional[int] = None





class AgentData(BaseModel):
    id : int
    agent_name : str
    mac_address : str|None
    host_name : str|None
    main_ip : str|None

    all_ips : list|None 
    os : str|None
    release : str|None
    version : str|None
    machine_architecture : str|None
    is_active : bool
    status : Optional[str] = None
    group_name: Optional[str] = None


class AgentStatusCount(BaseModel):
    total : Optional[int] = 0
    active : Optional[int] = 0
    disconnected : Optional[int] = 0
    pending : Optional[int] = 0
    never_connected : Optional[int] = 0


class AgentOSCount(BaseModel):
    os_name:str
    os_count:int


class AgentGroupCount(BaseModel):
    group_name: str
    group_count: int


class GetAgentsResponse(BaseModel):
    agent_status_count : AgentStatusCount
    agent_os_count : list[AgentOSCount]
    agent_group_count : list[AgentGroupCount]
    agents : list[AgentData]



class IsValidAgentNameResponse(BaseModel):
    valid : bool



class ExistingGroup(BaseModel):
    group_id:int
    group_name : str


class ExistingGroupsResponse(BaseModel):
    groups : list[ExistingGroup]


class AgentInstallationCommandResponse(BaseModel):
    installation_command : str
    running_command : str

    