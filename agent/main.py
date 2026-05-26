from config.config import DEFAULT_CONFIG
from agent import SentinelAgent
import signal
import sys


def main():

    config = DEFAULT_CONFIG.copy()

    agent = SentinelAgent(config , "TestAgent")

    def _sig_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT,  _sig_handler)

    agent.start()
    agent.wait()


if __name__ == "__main__":
    main()
