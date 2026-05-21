from enum import Enum
from dataclasses import dataclass
from typing import Optional

class AuthEventAction(str, Enum):
    LOGIN       = "login"
    LOGOUT      = "logout"
    LOGIN_FAIL  = "login_failed"
    SUDO        = "sudo"
    SSH_ACCEPT  = "ssh_accepted"
    SSH_FAIL    = "ssh_failed"
    PASSWD_CHG  = "password_change"
    USER_ADD    = "user_add"
    USER_DEL    = "user_delete"


@dataclass
class AuthInfo:
    method:         Optional[str]  = None   # password | key | token | kerberos
    source_ip:      Optional[str]  = None
    source_port:    Optional[int]  = None
    destination:    Optional[str]  = None
    failure_reason: Optional[str]  = None
    sudo_command:   Optional[str]  = None
    pam_module:     Optional[str]  = None
    session_type:   Optional[str]  = None   # ssh | tty | pts | rdp
