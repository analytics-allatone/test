# from sqlalchemy.future import select
# from fastapi import APIRouter , Depends , HTTPException , status
# from sqlalchemy.ext.asyncio import AsyncSession
# from pathlib import Path
# import base64


# ###############################################
# #                                             #
# #              LOCAL MODULES IMPORT           #
# #                                             #
# ###############################################
# from db.db import  get_async_db
# from utils.machine_validator import validate_ssh , run_ssh_command , upload_folder_with_identity
# from schemas.v1.standard_schema import standard_success_response
# from schemas.v1.machine_management_schema import(
#     ValidateMachineRequest , ValidateMachineResponse,
#     AddMachineRequest , AddMachineResponse
# )

# from models.master_model import User , AgentDBData

# from auth.jwt_auth import verify_token








# @machine_management_router.post("/validate-machine" , response_model = standard_success_response[ValidateMachineResponse] , status_code=200)
# async def ValidateMachine(req : ValidateMachineRequest):
#     host = req.host
#     username = req.username
#     password = req.password
#     private_key = base64.b64decode(req.private_key).decode()
#     auth_type = req.auth_type
#     port = req.port

#     valid = await validate_ssh(host = host , username = username ,  password=password , private_key= private_key , port = port , auth_type= auth_type)
#     if valid:
#         response = ValidateMachineResponse()
#         return standard_success_response(data = response , message = "Machine validated successfully")
    
#     raise HTTPException(
#         status_code=401,
#         detail="SSH authentication failed"
#     )




# @machine_management_router.post("/add-machine" , response_model = standard_success_response[AddMachineResponse] , status_code=201)
# async def addMachine(req: AddMachineRequest ,  db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_token)):
#     host = req.host
#     username = req.username
#     password = req.password
#     bs4_key = req.private_key
#     private_key = base64.b64decode(req.private_key).decode()
#     auth_type = req.auth_type
#     auth_type 
#     port = req.port

#     name = req.name
#     cloud_provider = req.cloud_provider
#     region = req.region
#     os_type = req.os_type
#     os_type = os_type.lower()
#     user_id = user.get('id')
    
#     is_valid = await validate_ssh(host = host , username = username ,  password=password , private_key= private_key , port = port , auth_type= auth_type)
    
#     if not is_valid:
#         raise HTTPException(
#         status_code=401,
#         detail="SSH authentication failed"
#     )

#     this_machine = Machines(
#         name = name,
#         host = host,
#         port = port,
#         username = username,

#         auth_type = auth_type,
#         private_key = bs4_key,
#         password = password,

#         cloud_provider = cloud_provider,
#         region = region,
#         os_type = os_type,
#         user_id = user_id

#     )

#     db.add(this_machine)

#     await db.commit()
#     await db.refresh(this_machine)

#     machine_id = this_machine.id 
#     BASE_DIR = Path("/app")

#     host  = this_machine.host
#     username= this_machine.username
#     local_path= f"{BASE_DIR}/agent"
#     remote_path= "/home/opc/agent"
#     port= this_machine.port
#     auth_type = this_machine.auth_type
#     private_key = base64.b64decode(this_machine.private_key).decode() if this_machine.private_key else None
#     password = this_machine.password
#     os_type = this_machine.os_type
#     print(private_key)
    

#     ret_data = await upload_folder_with_identity(host = host ,username = username ,machine_id = machine_id , local_path=local_path, remote_path= remote_path , password = None , private_key = private_key , auth_type = auth_type , os_type=os_type)
#     print(ret_data)
#     response = AddMachineResponse(

#         id  = this_machine.id,
#         name = this_machine.name,
#         host = this_machine.host,
#         port = this_machine.port,
#         username = this_machine.username,
#         auth_type = this_machine.auth_type,
#         private_key = this_machine.private_key,
#         password = this_machine.password,
#         cloud_provider = this_machine.cloud_provider,
#         region = this_machine.region,
#         os_type = this_machine.os_type,
#         is_active = this_machine.is_active
#     )

#     return standard_success_response(data = response , message = "Machine Added successfully")






# @machine_management_router.get("/upload-to-machine")
# async def ValidateMachine():

#     BASE_DIR = Path("/app")

#     host  = "80.225.239.163"
#     username= "opc"
#     local_path= f"{BASE_DIR}/agent"
#     remote_path= "/home/opc/agent"
#     port= 22
#     auth_type = "key"
#     private_key = '''-----BEGIN RSA PRIVATE KEY-----
# MIIEowIBAAKCAQEAnNfVhlpY3+Jz1tYsScliI9k17XiPPiXneRSwHFOjzwFX9Sj4
# +ArsNkyuW9rZ4WG/tJ8mjDHZoDe0L5XMyG05cT2o0eqc5nPeCbw90+ryUceTT2V4
# jjqiq8VNo8zhtMYUWa9wwh0dRwSkvUAEnRHFcBg1al7wS/QG1dGrh26GxmnNs0gm
# t2OjzF+AITJRgp52EbHw6OL1n+Ut6Llz1HuS7+ySKoV367mZ9TckQtWSypG1vjyG
# L4AlW9y3C8rEkTEDBDgsvBeaGsiOmYyMmKn+3fpS9S7lQyr7E/aDCUKvS92+2AZd
# zuJEQdy3VgWzdSOICEkfzzKdzoWSEeQsPkLS2QIDAQABAoIBABhW2CW8JyxAeJMq
# HlT/AZH9lwRN4AYYHLvUouBqdwex4NlEgp+qFkOg57KNG6BW/8htpYOTstQjANJy
# RTAEidRRv2fVUtmNDokP42pbpz9bS2LCpOWGzOVUviUsBLSobn0HyuWcs1qTf7sh
# +vVNo4gvLDmLF8WO+MaSqIiLoDJG96bri+sv7HMnHcK1Yza/1VeE/uQv1ZGmvHdI
# NZR5Tg0kqEzBPqzp6pgEjvMHLQ/y8CZfccYsR9mywMUC7gZPNaj2n1dTRSjI4H1G
# kWzScS0Ebyx2c3KQWPFG8i0I5DG61minFzij2HwghojY2rgo1Jo9zOlHUNB10/l4
# yj1nX6cCgYEA1zCemW/xMpdmYIO22+u7gpmmzE+cAhDZAVzJYNjJG4a5kOwkRj//
# AfK/hGUUKYjRSC7+6JhBSh1BI5M6f9TE+VcLGv6u11Qg//u2oauSfwa59+YTDzdD
# Qxpk46Tll5ENDF/NDcWlUREjgGJ70KGOhLDP5xNu1bUUGiUIg3aiUi8CgYEAupaA
# P82f1frRCR25VU632tiqM2QRJQ0C7tzufNRhw/WSeEY3HxChobcISW7WbnF5Enwd
# wdSyUovSyWYWM6nitdrL+XrbU2tcNQw4ZZHGy323mxgYmG4a3xr0FkLyUkJa/a/e
# uzyD6PEjvcLo5iUFAOo+WG9nr0CQlzXS8/VekXcCgYEAxKlEaMnrTucawx3c4gQA
# LA0saRBgbWrkR+B6ki3NLYDk2lNVm3YlIayt5ttRn9vQF/4LLJrpIEi4HUESd30G
# PzGTjqovM89JEWkDsaDRk5GcJ7h2trM0n4Dhr0ImKWyA1kw/ZFS7Dulw3oYizbq4
# OwA0IOSbqGeC5Znuu+aR1jUCgYAxT6UFN6qOOoMUDa71RKCCTdBtVHzTdeTYi7rb
# cqWDzFqxPp1CsHqG6oBeJ9Szy3lb0UFsAHJALoO+hiRH8xXfSbuuazGbkjwEKP6e
# mTAYh1kGvA+D+VVQsSbg20B/TNoPQXNzuEKERXZUqDY03IO+AioH5SlZv45259qg
# brBXcQKBgAQ7NyA3gQBuQ5dQSaYqunQuaw30PVpsYIBuTjlvi+l3ddi//4a23nPC
# 3MazTdTjfMcz7ek/0Xh8vdiYViMWanUSGu36UN85EZiLRAN+3QiOWpUM+IvNm2vp
# 9XPonvWzSvwUEaecZXrpo2JD5cS8z38GhILzTlXFX18zCGwB80Od
# -----END RSA PRIVATE KEY-----'''


#     machine_id = 60 
#     kafka_broker= "kafka_broker"
#     kafka_topic= "kafka_topic"
    

#     ret_data = await upload_folder_with_identity(host = host ,username = username ,machine_id = machine_id , kafka_broker= kafka_broker , kafka_topic= kafka_topic, local_path=local_path , remote_path= remote_path , password = None , private_key = private_key , auth_type = auth_type)
#     return {"success" : "Done" , "data" : ret_data}