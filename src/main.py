from contextlib import asynccontextmanager
import asyncio

import os
from fastapi import FastAPI , Request , APIRouter
from fastapi.responses import PlainTextResponse , FileResponse
from fastapi.middleware.cors import CORSMiddleware

from api.v1 import v1_api_router
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from db.db import create_db_and_tables
import sys
from bots.mqtt_consumer import mqtt_background_consumer


worker_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):

    global worker_task

    # # DATABASE STARTUP
    await create_db_and_tables()


    worker_task = asyncio.create_task(mqtt_background_consumer())

    print("Application Started")

    yield

    # SHUTDOWN LOGIC
    print("Application Shutting Down...")
    worker_task.cancel()


app = FastAPI(
    lifespan=lifespan
)


HERE = os.path.dirname(os.path.abspath(__file__))


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(v1_api_router , prefix="/api")



# @app.get("/")
# def root():
#     return {
#         "APPLICATION": "RUNNING"
#     }


# @app.get("/install_service.ps1", response_class=PlainTextResponse)
# def install_ps1(request : Request):
#     text = open(os.path.join(HERE, "a.ps1"), encoding="utf-8").read()
#     base = str(request.base_url).rstrip("/")          # e.g. https://agents.example.com
#     return text.replace("https://YOUR_HOST", base)

# @app.get("/binaries/{name}", response_class=FileResponse)
# def install_ps1(name: str):
#     safe = os.path.basename(name)                  # strips ../ to block path traversal
#     path = os.path.join(HERE, safe)
#     print(path)
#     if not os.path.isfile(path):
#         print("Not FOund")
#         raise 
#     return FileResponse(path, media_type="application/octet-stream", filename=safe)



# @app.get("/healthCheck")
# def health_check():
#     return {
#         "status": "Success"
#     }




def resource_path(rel):
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS          # PyInstaller's bundled-files location
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)

FRONTEND_DIR = resource_path(os.path.join("frontend", "build"))
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "build")   # CRA -> build
# STATIC_DIR = os.path.join(FRONTEND_DIR, "static")            # CRA -> static

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
else:
    print(f"WARNING: frontend build not found at {FRONTEND_DIR}. Run `npm run build`.")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # Serve real root-level files (favicon.ico, manifest.json, logo192.png, etc.)
    candidate = os.path.normpath(os.path.join(FRONTEND_DIR, full_path))
    if full_path and candidate.startswith(FRONTEND_DIR) and os.path.isfile(candidate):
        return FileResponse(candidate)
    # Fall back to index.html for client-side routing
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
    return {"detail": "Frontend not built yet. Run `npm run build` in the frontend folder."}