#####################################
#                                   #
#       LOGGING CONFIGURATIONS      #
#                                   #
#####################################


JSON_LOGS_DIR = "/logs"
JSON_LOGS_BASENAME = "logs-of"







######################################
#                                    #
#         AGENT CONFIGURATIONS       #
#                                    #
######################################

DEFAULT_CONFIG = {
    
    "output": {
        "stdout": False,

        "kafka": {
            "brokers": "80.225.239.163:9092",
            "topic": "agent-events"
        }
    },
    
    "collectors": {
        "file": {
            "enabled":     True,
            "watch_paths": None,        # None = use defaults per OS
            "ignore_dirs": None,        # None = use defaults per OS
            "recursive":   True,
            "use_polling": False,
        },
        "auth": {
            "enabled":       True,
            "log_path":      None,      # None = auto-detect
            "parse_history": False,
            "poll_interval": 5,         # Windows only
        },
        "network": {
            "enabled":       True,
            "poll_interval": 2.0,        # Time in Seconds
            "track_bandwidth": True,
        },
        "process": {
            "enabled":           True,
            "poll_interval":     1.5,    # Time in Seconds
            "resource_interval": 30.0,
            "hash_executables":  True,
        },
        "usb": {
            "enabled": True,
            "poll_interval": 3.0,
            "scan_on_connect": True,
            "transfer_threshold_bytes": 524288000,
        },
        "harddisk": {
            "enabled": True,
            "poll_interval": 30.0,
            "smart_interval": 300.0,
            "warn_percent": 85.0,
            "critical_percent": 95.0,
            "enable_smart": True,
        },
    },
    "filters": {
        "min_severity": "info",         # info | low | medium | high | critical
        "exclude_categories": [],
        "exclude_actions": [],
    }
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
