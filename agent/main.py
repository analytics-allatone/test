from config.config import DEFAULT_CONFIG
from agent import SentinelAgent
import signal
import sys
import json
from pathlib import Path
import argparse
# from runtime_config import SERVER_IP, AGENT_NAME
def run_tim():
        parser = argparse.ArgumentParser()

        parser.add_argument("--server-ip",required=True)
        parser.add_argument("--server-port",type=int,default=8000)
        # parser.add_argument("--mqtt-host")
        parser.add_argument("--mqtt-port",type=int,default=1883)
        parser.add_argument("--agent-name",required=True)

        return  parser.parse_args()
def main():
    try:
        import runtime_config

        server_ip = runtime_config.SERVER_IP
        agent_name = runtime_config.AGENT_NAME

    except ImportError:
        args = run_tim()

        server_ip = args.server_ip
        agent_name = args.agent_name

        with open("runtime_config.py", "w") as f:
            f.write(
                f'SERVER_IP = "{server_ip}"\n'
                f'AGENT_NAME = "{agent_name}"\n'
            )

    config = DEFAULT_CONFIG.copy()

    agent = SentinelAgent(config ,agent_name)
    def _sig_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT,  _sig_handler)

    agent.start()
    agent.wait()

if __name__ == "__main__": 
    main()
