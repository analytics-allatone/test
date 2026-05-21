from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.v1 import v1_api_router
from db.db import create_db_and_tables

from bots.mqtt_consumer import mqtt_background_consumer


worker_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):

    global worker_task

    # # DATABASE STARTUP
    await create_db_and_tables("master_database")


    worker_task = asyncio.create_task(mqtt_background_consumer())

    print("Application Started")

    yield

    # SHUTDOWN LOGIC
    print("Application Shutting Down...")
    worker_task.cancel()


app = FastAPI(
    lifespan=lifespan
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(v1_api_router , prefix="/v1")


@app.get("/")
def root():
    return {
        "APPLICATION": "RUNNING"
    }


@app.get("/healthCheck")
def health_check():
    return {
        "status": "Success"
    }