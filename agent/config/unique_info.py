import os
import sys
from dotenv import load_dotenv

def app_dir() -> str:
    """Folder the binary lives in. When frozen by Nuitka, sys.executable is the
    binary itself, so the .env is found regardless of how the service launches
    it (systemd, launchd, Windows service) and regardless of the working dir."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
 
 
load_dotenv(os.path.join(app_dir(), ".env"))
 
AGENT_NAME = os.getenv("AGENT_NAME")
SERVER_IP = os.getenv("SERVER_IP")
