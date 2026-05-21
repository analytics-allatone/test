from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status
from sqlalchemy.ext.asyncio import AsyncSession




###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################

from db.db import  get_async_db
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.auth_schema import(
    LoginRequest , LoginResponse,
    SignupRequest , SignupResponse,
    RefreshAccessTokenRequest , RefreshAccessTokenResponse
)
from auth.crypto import hash_password , verify_password

from models.master_model import User

from auth.jwt_auth import create_access_token , create_refresh_token , verify_token






auth_router = APIRouter()




@auth_router.post("/login" , response_model = standard_success_response[LoginResponse] , status_code=200)
async def login(req: LoginRequest ):
    email = req.email
    password = req.password
    user = None
    async with get_async_db("master_database") as db:

        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        
    
    if not user:
        raise HTTPException(status_code=401, detail="Email do not exist , Signup")
    
    if not verify_password(password , user.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    token_data = {
        "id" : user.id,
        "email": user.email
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    response = LoginResponse(access_token = access_token , refresh_token = refresh_token)
    return  standard_success_response(data = response , message = "Logged in successfully")







@auth_router.post("/signup" , response_model = standard_success_response[SignupResponse] , status_code=201)
async def signup(req: SignupRequest ):
    token_data = None
    async with get_async_db("master_database") as db:
        result = await db.execute(select(User).where(User.email == req.email))
        existing_user = result.scalars().first()
    
        if existing_user:
            raise HTTPException(status_code=401, detail="User already exists with this email, please login")
        

        hashed_password = hash_password(req.password)

        new_user = User(
            first_name = req.first_name,
            last_name = req.last_name,
            email = req.email,
            country_code = req.country_code,
            phone_number = req.phone_number,
            password = hashed_password
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        token_data = {
            "id" : new_user.id,
            "email": new_user.email
        }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    response = SignupResponse(access_token = access_token , refresh_token = refresh_token)
    return  standard_success_response(data = response , message = "Signed in successfully")



 




@auth_router.post("/refresh-access-token" , response_model = standard_success_response[RefreshAccessTokenResponse] , status_code=200)
async def refreshAccessToken(req: RefreshAccessTokenRequest):

    payload = verify_token(req.refresh_token)
    
    token_data = {
        "id" : payload["id"],
        "email": payload["email"],
    }

    access_token = create_access_token(token_data)
    response = RefreshAccessTokenResponse(access_token = access_token)
    
    return  standard_success_response(data = response , message = "New Access token generated successfully")
