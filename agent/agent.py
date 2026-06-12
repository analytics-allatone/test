import time
import platform

from config.config import SEVERITY_ORDER 

from output.writer import EventDispatcher
from collectors.file_collector import FileCollector
from collectors.auth_collector import create_auth_collector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.usb_collector import USBCollector
from collectors.harddisk_collector import HardDiskCollector
from utils import get_machine_info

from dotenv import load_dotenv
import os
load_dotenv("./.env")






class SentinelAgent:
    def __init__(self, config: dict , agent_name:str=os.getenv("name")):
        self.config     = config
        self._collectors = []
        self._dispatcher = None
        self._running   = False
        self.machine_info = get_machine_info()
        self.machine_info["agent_name"] = agent_name

    def _build_dispatcher(self):
        cfg = self.config["output"]

        return EventDispatcher(
            stdout=cfg.get("stdout", False),server_ip= os.getenv("IP"),
        )

    def _make_dispatch(self):
        """Returns a filtered dispatch function."""
        cfg          = self.config.get("filters", {})
        min_sev_str  = cfg.get("min_severity", "info")
        min_sev_idx  = SEVERITY_ORDER.index(min_sev_str) if min_sev_str in SEVERITY_ORDER else 0
        excl_cats    = set(cfg.get("exclude_categories", []))
        excl_actions = set(cfg.get("exclude_actions", []))

        def dispatch(event_dict: dict , machine_info):
            sev = event_dict.get("severity", "info")
            if SEVERITY_ORDER.index(sev) < min_sev_idx:
                return
            if event_dict.get("category") in excl_cats:
                return
            if event_dict.get("action") in excl_actions:
                return
            self._dispatcher.push(event_dict , machine_info)

        return dispatch

    def start(self):
        self._dispatcher = self._build_dispatcher()
        dispatch = self._make_dispatch()
        try:
            
            fc = FileCollector(
                dispatch    = dispatch,
                machine_info= self.machine_info,
                watch_paths = None,
                ignore_dirs = None,
                recursive   = True,
                use_polling = False,
            )
            fc.start()
            self._collectors.append(fc)
            print("✓ File Collector started")
        except ImportError as e:
            print(f"File collector unavailable: {e}")
        except Exception as e:
            print(f"File collector error: {e}")


        try:
            
            ac = create_auth_collector(
                dispatch       = dispatch,
                machine_info = self.machine_info
            )
            ac.start()
            self._collectors.append(ac)
            print("Auth Collector started")
        except Exception as e:
            print(f"Auth collector error: {e}")

        try:
            
            nc = NetworkCollector(
                dispatch        = dispatch,
                machine_info= self.machine_info,
                poll_interval   = 2.0,
                track_bandwidth = True
            )
            nc.start()
            self._collectors.append(nc)
            print(" Network Collector started")
        except Exception as e:
            print(f"Network collector error: {e}")

        try:
            
            pc = ProcessCollector(
                dispatch          = dispatch,
                machine_info= self.machine_info,
                poll_interval     = 1.5,
                resource_interval = 30.0,
                hash_executables  = True
            )
            pc.start()
            self._collectors.append(pc)
            print("Process Collector started")
        except Exception as e:
            print(f"Process collector error: {e}")


        try:
            uc = USBCollector(
                dispatch                 = dispatch,
                machine_info= self.machine_info,
                poll_interval            = 3.0,
                scan_on_connect          = True,
                transfer_threshold_bytes = 524288000,
            )
            uc.start()
            self._collectors.append(uc)
            print("USB Collector started")
        except Exception as e:
            print(f"USB collector error: {e}")

        # Hard Disk collector
        # hd_cfg = col_cfg.get("harddisk", {})
        # if hd_cfg.get("enabled", True):
        #     try:
        #         hc = HardDiskCollector(
        #             dispatch         = dispatch,
        #             machine_info= self.machine_info,
        #             poll_interval    = hd_cfg.get("poll_interval", 30.0),
        #             smart_interval   = hd_cfg.get("smart_interval", 300.0),
        #             warn_percent     = hd_cfg.get("warn_percent", 85.0),
        #             critical_percent = hd_cfg.get("critical_percent", 95.0),
        #             enable_smart     = hd_cfg.get("enable_smart", True),
        #         )
        #         hc.start()
        #         self._collectors.append(hc)
        #         print("HardDisk Collector started")
        #     except Exception as e:
        #         print(f"HardDisk collector error: {e}")
        self._running = True
        print(f"Agent running.")
        print("Press Ctrl+C to stop.")

    def stop(self):
        print("Stopping collectors...")
        for c in self._collectors:
            try:
                c.stop()
            except Exception:
                pass
        if self._dispatcher:
            self._dispatcher.flush_and_stop()
        print("Sentinel Agent stopped.")

    def wait(self):
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()



def deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result
