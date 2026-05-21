from pydantic import BaseModel , model_validator
from typing import Optional
from enum import Enum


class AuthType(str, Enum):
    key = "key"
    password = "password"



from pydantic import BaseModel, Field, model_validator
from typing import Optional

class ValidateMachineRequest(BaseModel):
    host: str
    port: Optional[int] = 22
    username: str
    auth_type: AuthType

    private_key: Optional[str] = None

    password: Optional[str] = None

    @model_validator(mode="after")
    def check_auth(self):
        if self.auth_type == AuthType.key and not self.private_key:
            raise ValueError("private_key is required when auth_type is 'key'")

        if self.auth_type == AuthType.password and not self.password:
            raise ValueError("password is required when auth_type is 'password'")

        return self
    

class ValidateMachineResponse(BaseModel):
    machine_validated : Optional[bool] = True




class AddMachineRequest(BaseModel):
    name: str
    host: str
    port: Optional[int] = 22
    username: str
    auth_type: AuthType
    private_key: Optional[str] = None
    password: Optional[str] = None
    cloud_provider: str
    region : Optional[str] = None
    os_type: str

    @model_validator(mode="after")
    def check_auth(self):
        if self.auth_type == AuthType.key and not self.private_key:
            raise ValueError("private_key is required when auth_type is 'key'")

        if self.auth_type == AuthType.password and not self.password:
            raise ValueError("password is required when auth_type is 'password'")

        return self

class AddMachineResponse(BaseModel):
    id : int
    name: str
    host: str
    port: Optional[int] = 22
    username: str
    auth_type: AuthType
    private_key: Optional[str] = None
    password: Optional[str] = None
    cloud_provider: str
    region : Optional[str]
    os_type: str
    is_active : bool