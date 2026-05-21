import re
import os
import time
import platform
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from schema.event_schema import (
    SentinelEvent, AuthInfo, UserInfo, ProcessInfo,
    EventCategory, EventAction, EventOutcome, Severity,
    get_host_info
)

# ─────────────────────────────────────────────
#  LINUX AUTH LOG PARSER
# ─────────────────────────────────────────────

# Regex patterns for common auth log entries
PATTERNS = {
    # sshd: Accepted password/publickey
    "ssh_accept": re.compile(
        r"sshd\[(\d+)\]: Accepted (\S+) for (\S+) from ([\d.a-fA-F:]+) port (\d+)"
    ),
    # sshd: Failed password/publickey
    "ssh_fail": re.compile(
        r"sshd\[(\d+)\]: Failed (\S+) for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port (\d+)"
    ),
    # sshd: Invalid user
    "ssh_invalid": re.compile(
        r"sshd\[(\d+)\]: Invalid user (\S+) from ([\d.a-fA-F:]+)"
    ),
    # sshd: Disconnected
    "ssh_disconnect": re.compile(
        r"sshd\[(\d+)\]: Disconnected from (?:authenticating user )?(\S+)? ?([\d.a-fA-F:]+) port (\d+)"
    ),
    # sudo: command execution
    "sudo": re.compile(
        r"sudo:\s+(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)"
    ),
    # sudo: authentication failure
    "sudo_fail": re.compile(
        r"sudo:\s+(\S+)\s*:\s*(\d+) incorrect password attempt"
    ),
    # PAM: session opened
    "pam_open": re.compile(
        r"(pam_unix|pam_sss)\((\S+):session\): session opened for user (\S+)"
    ),
    # PAM: session closed
    "pam_close": re.compile(
        r"(pam_unix|pam_sss)\((\S+):session\): session closed for user (\S+)"
    ),
    # PAM: auth failure
    "pam_fail": re.compile(
        r"(pam_unix|pam_sss)\((\S+):auth\): authentication failure.*user=(\S+)"
    ),
    # su: successful
    "su_success": re.compile(
        r"su\[(\d+)\]: Successful su for (\S+) by (\S+)"
    ),
    # su: failed
    "su_fail": re.compile(
        r"su\[(\d+)\]: FAILED su for (\S+) by (\S+)"
    ),
    # useradd / userdel
    "useradd": re.compile(r"useradd\[(\d+)\]: new user: name=(\S+)"),
    "userdel":  re.compile(r"userdel\[(\d+)\]: delete user '(\S+)'"),
    # passwd change
    "passwd": re.compile(r"passwd\[(\d+)\]: password changed for (\S+)"),
    # Login from login/getty
    "login_success": re.compile(r"login\[(\d+)\]: ROOT LOGIN|login\[(\d+)\]: LOGIN ON \S+ BY (\S+)"),
    # systemd-logind
    "logind_login":  re.compile(r"systemd-logind\[(\d+)\]: New session (\S+) of user (\S+)"),
    "logind_logout": re.compile(r"systemd-logind\[(\d+)\]: Removed session (\S+)"),
    # cron
    "cron": re.compile(r"CRON\[(\d+)\]: \((\S+)\) CMD \((.*)\)"),
}

MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

def _parse_timestamp(ts_str: str) -> str:
    """Parse syslog timestamp like 'Jun 15 14:32:01' to ISO8601."""
    try:
        parts = ts_str.split()
        month = MONTH_MAP.get(parts[0], 1)
        day   = int(parts[1])
        t     = parts[2]
        year  = datetime.now().year
        h, m, s = map(int, t.split(":"))
        dt = datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_auth_line(line: str, dispatch: Callable , machine_info):
    """Parse a single auth log line and emit a SentinelEvent if matched."""
    print(f"[RAW AUTH LOG] {line.rstrip()}")
    line = line.strip()
    if not line:
        return

    # Extract syslog prefix: "Jun 15 14:32:01 hostname process[pid]: message"
    syslog_re = re.match(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)", line
    )
    timestamp = datetime.now(timezone.utc).isoformat()
    if syslog_re:
        timestamp = _parse_timestamp(syslog_re.group(1))
        msg       = syslog_re.group(3)
    else:
        msg = line

    event = None

    # ── SSH ──────────────────────────────────
    m = PATTERNS["ssh_accept"].search(msg)
    if m:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.SSH_ACCEPT,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.INFO,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["ssh", "authentication"],
            user      = UserInfo(name=m.group(3)),
            auth      = AuthInfo(
                method      = m.group(2),  # password|publickey
                source_ip   = m.group(4),
                source_port = int(m.group(5)),
                session_type= "ssh",
            ),
            process   = ProcessInfo(pid=int(m.group(1)), name="sshd"),
        )
    
    m = PATTERNS["ssh_fail"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.SSH_FAIL,
            outcome   = EventOutcome.FAILURE,
            severity  = Severity.HIGH,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["ssh", "authentication", "brute_force_candidate"],
            user      = UserInfo(name=m.group(3)),
            auth      = AuthInfo(
                method         = m.group(2),
                source_ip      = m.group(4),
                source_port    = int(m.group(5)),
                session_type   = "ssh",
                failure_reason = "bad credentials",
            ),
            process   = ProcessInfo(pid=int(m.group(1)), name="sshd"),
            mitre_tactic    = "Credential Access",
            mitre_technique = "T1110",
        )

    m = PATTERNS["sudo"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.SUDO,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.MEDIUM,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["sudo", "privilege_escalation"],
            user      = UserInfo(name=m.group(1), terminal=m.group(2)),
            auth      = AuthInfo(
                sudo_command = m.group(5).strip(),
                method       = "sudo",
            ),
            mitre_tactic    = "Privilege Escalation",
            mitre_technique = "T1548.003",
        )

    m = PATTERNS["pam_fail"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.LOGIN_FAIL,
            outcome   = EventOutcome.FAILURE,
            severity  = Severity.MEDIUM,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["pam", "authentication"],
            user      = UserInfo(name=m.group(3)),
            auth      = AuthInfo(
                method         = "pam",
                pam_module     = m.group(1),
                session_type   = m.group(2),
                failure_reason = "authentication failure",
            ),
        )

    m = PATTERNS["useradd"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.USER_ADD,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.HIGH,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["user_management", "persistence_candidate"],
            user      = UserInfo(name=m.group(2)),
            process   = ProcessInfo(pid=int(m.group(1)), name="useradd"),
            mitre_tactic    = "Persistence",
            mitre_technique = "T1136",
        )

    m = PATTERNS["userdel"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.USER_DEL,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.HIGH,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["user_management"],
            user      = UserInfo(name=m.group(2)),
        )

    m = PATTERNS["passwd"].search(msg)
    if m and not event:
        event = SentinelEvent(
            timestamp = timestamp,
            category  = EventCategory.AUTH,
            action    = EventAction.PASSWD_CHG,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.MEDIUM,
            collector = "auth_log",
            host      = get_host_info(),
            raw_log   = line,
            tags      = ["credential_change"],
            user      = UserInfo(name=m.group(2)),
        )

    if event:
        dispatch(event.to_dict() , machine_info)





class LinuxAuthCollector:
    """Tails /var/log/auth.log (or /var/log/secure) in real time."""

    AUTH_LOG_CANDIDATES = [
        "/var/log/auth.log",    # Debian/Ubuntu
        "/var/log/secure",      # RHEL/CentOS/Fedora
        "/var/log/messages",    # Some distros
    ]

    def __init__(self, dispatch: Callable,  machine_info: dict,log_path: str = None,
                 parse_history: bool = False):
        self._dispatch = dispatch
        self._log_path = log_path or self._find_log()
        self._parse_history = parse_history
        self._stop = threading.Event()
        self._thread = None
        self._machine_info =  machine_info

    def _find_log(self) -> str:
        for p in self.AUTH_LOG_CANDIDATES:
            if Path(p).exists():
                return p
        print("No auth log found. Checked: " + str(self.AUTH_LOG_CANDIDATES))
        return self.AUTH_LOG_CANDIDATES[0]

    def _tail(self):
        print(f"Tailing auth log: {self._log_path}")
        try:
            with open(self._log_path, "r", errors="replace") as f:
                if not self._parse_history:
                    f.seek(0, 2)  # seek to end
                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        parse_auth_line(line, self._dispatch , self._machine_info)
                    else:
                        time.sleep(0.05)
                        # Handle log rotation
                        try:
                            if Path(self._log_path).stat().st_ino != os.fstat(f.fileno()).st_ino:
                                print("Auth log rotated, reopening...")
                                break
                        except Exception:
                            break
        except PermissionError:
            print(f"Permission denied reading {self._log_path}. Run as root.")
        except FileNotFoundError:
            print(f"Auth log not found: {self._log_path}")

    def start(self):
        self._thread = threading.Thread(target=self._tail, daemon=True, name="auth-tail")
        self._thread.start()

    def stop(self):
        self._stop.set()




class WindowsAuthCollector:
    """
    Reads Windows Security Event Log for auth events.
    Requires pywin32: pip install pywin32
    Event IDs:
      4624 - Successful logon
      4625 - Failed logon
      4634 - Logoff
      4648 - Explicit credential logon
      4720 - User account created
      4726 - User account deleted
      4738 - User account changed
      4800 - Workstation locked
      4801 - Workstation unlocked
    """

    LOGON_TYPES = {
        2: "interactive", 3: "network", 4: "batch", 5: "service",
        7: "unlock", 8: "network_cleartext", 9: "new_credentials",
        10: "remote_interactive", 11: "cached_interactive",
    }

    EVENT_MAP = {
        4624: (EventAction.LOGIN,      EventOutcome.SUCCESS, Severity.INFO,   "logon"),
        4625: (EventAction.LOGIN_FAIL, EventOutcome.FAILURE, Severity.HIGH,   "logon_failed"),
        4634: (EventAction.LOGOUT,     EventOutcome.SUCCESS, Severity.INFO,   "logoff"),
        4648: (EventAction.LOGIN,      EventOutcome.SUCCESS, Severity.MEDIUM, "explicit_credential"),
        4720: (EventAction.USER_ADD,   EventOutcome.SUCCESS, Severity.HIGH,   "user_created"),
        4726: (EventAction.USER_DEL,   EventOutcome.SUCCESS, Severity.HIGH,   "user_deleted"),
        4738: (EventAction.PASSWD_CHG, EventOutcome.SUCCESS, Severity.MEDIUM, "account_changed"),
    }

    def __init__(self, dispatch: Callable, machine_info: dict, poll_interval: int = 5):
        self._dispatch      = dispatch
        self._poll_interval = poll_interval
        self._stop          = threading.Event()
        self._last_record   = 0
        self._thread        = None
        self._machine_info =  machine_info

    def _read_events(self):
        try:
            import win32evtlog, win32con, win32evtlogutil, winerror
        except ImportError:
            print("pywin32 not installed. Run: pip install pywin32")
            return

        server   = None
        log_type = "Security"
        flags    = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        hand     = win32evtlog.OpenEventLog(server, log_type)

        while not self._stop.is_set():
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for ev in events:
                    if ev.RecordNumber <= self._last_record:
                        continue
                    self._last_record = ev.RecordNumber
                    eid = ev.EventID & 0xFFFF
                    if eid in self.EVENT_MAP:
                        self._process_event(ev, eid)
            except Exception as ex:
                print(f"Windows event read: {ex}")
            time.sleep(self._poll_interval)

    def _process_event(self, ev, eid: int):
        try:
            import win32evtlogutil
            action, outcome, severity, tag = self.EVENT_MAP[eid]
            strings = ev.StringInserts or []

            user_name = strings[5] if len(strings) > 5 else None
            src_ip    = strings[18] if len(strings) > 18 else None
            logon_type= int(strings[8]) if len(strings) > 8 and strings[8].isdigit() else None

            ts = ev.TimeGenerated.isoformat()

            event = SentinelEvent(
                timestamp = ts,
                category  = EventCategory.AUTH,
                action    = action,
                outcome   = outcome,
                severity  = severity,
                collector = "windows_eventlog",
                host      = get_host_info(),
                raw_log   = f"EventID={eid}",
                tags      = ["windows", "authentication", tag],
                user      = UserInfo(name=user_name),
                auth      = AuthInfo(
                    source_ip    = src_ip,
                    session_type = self.LOGON_TYPES.get(logon_type, str(logon_type)) if logon_type else None,
                    method       = "password",
                ),
            )
            if eid == 4625:
                event.mitre_tactic    = "Credential Access"
                event.mitre_technique = "T1110"

            self._dispatch(event.to_dict(), self._machine_info)
        except Exception as ex:
            print(f"Event parse error: {ex}")

    def start(self):
        self._thread = threading.Thread(target=self._read_events, daemon=True, name="win-evtlog")
        self._thread.start()

    def stop(self):
        self._stop.set()



def create_auth_collector(dispatch: Callable, machine_info):
    if platform.system() == "Windows":
        return WindowsAuthCollector(dispatch,machine_info)
    return LinuxAuthCollector(dispatch,machine_info)
