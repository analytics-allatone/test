from enum import Enum
from typing import Optional , List
from dataclasses import dataclass ,  field


class ProcessEventAction(str , Enum):
    START       = "start"
    STOP        = "stop"
    INJECT      = "inject"
    OPEN_FILE   = "open_file"





@dataclass
class ProcessInfo:
    pid:            Optional[int]  = None
    ppid:           Optional[int]  = None
    name:           Optional[str]  = None
    executable:     Optional[str]  = None
    command_line:   Optional[str]  = None
    args:           List[str]      = field(default_factory=list)
    working_dir:    Optional[str]  = None
    start_time:     Optional[str]  = None
    end_time:       Optional[str]  = None
    exit_code:      Optional[int]  = None
    user:           Optional[str]  = None
    cpu_percent:    Optional[float]= None
    memory_rss_mb:  Optional[float]= None
    open_files:     List[str]      = field(default_factory=list)
    sha256:         Optional[str]  = None   # hash of the executable
