import time
import platform
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, Optional
from pathlib import Path

import psutil

# Importing custom flat schema variables
from schema.process_schema import ProcessEvent, EventCategory, EventOutcome, Severity
from schema.event_schema import hash_file  # Retaining file hashing utility function

# Living-off-the-Land Binaries (LOLBins)
LOLBINS_LINUX = {
    "python", "python3", "perl", "ruby", "php", "node",
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    "base64", "xxd", "dd", "bash", "sh", "zsh",
    "awk", "sed", "xargs", "find", "tar", "gzip",
    "openssl", "gpg", "ssh", "scp", "sftp", "rsync",
    "nmap", "tcpdump", "wireshark", "tshark", "strace",
    "gdb", "ltrace", "at", "crontab", "screen", "tmux",
}

LOLBINS_WINDOWS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "regsvcs.exe",
    "msiexec.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "forfiles.exe", "schtasks.exe", "at.exe", "sc.exe",
    "net.exe", "net1.exe", "nltest.exe", "whoami.exe",
    "mimikatz.exe", "psexec.exe", "wevtutil.exe",
    "bcdedit.exe", "vssadmin.exe", "reg.exe",
}

SUSPICIOUS_NAMES = {
    "mimikatz", "meterpreter", "empire", "cobalt", "cobaltstrike",
    "msf", "shellcode", "exploit", "payload", "backdoor", "trojan",
    "ransomware", "cryptominer", "xmrig", "minerd", "kthreadd2",
}

SUSPICIOUS_ARGS = [
    "-enc", "-encodedcommand", "frombase64string", "invoke-expression",
    "iex(", "downloadstring", "bypass", "hidden", "-windowstyle hidden",
    "/c powershell", "cmd /c", "certutil -decode", "bitsadmin /transfer",
    "echo.*|.*base64", "wget.*|.*bash", "curl.*|.*bash",
]

HIGH_CPU_THRESHOLD    = 80.0   # %
HIGH_MEMORY_MB        = 1024   # MB


def _assess_process(name: str, exe: str, cmdline: str) -> tuple:
    """Returns (severity, tags, mitre_technique)."""
    name_lower    = (name or "").lower()
    cmdline_lower = (cmdline or "").lower()
    tags = ["process"]

    lolbins = LOLBINS_WINDOWS if platform.system() == "Windows" else LOLBINS_LINUX
    is_lolbin = name_lower in lolbins or name_lower.rstrip(".exe") in lolbins

    for sus_name in SUSPICIOUS_NAMES:
        if sus_name in name_lower or sus_name in (exe or "").lower():
            return Severity.CRITICAL, tags + ["malware_name"], "T1059"

    for sus_arg in SUSPICIOUS_ARGS:
        if sus_arg in cmdline_lower:
            if is_lolbin:
                return Severity.HIGH, tags + ["lolbin", "suspicious_args"], "T1059"
            return Severity.HIGH, tags + ["suspicious_args"], "T1059"

    if is_lolbin:
        return Severity.MEDIUM, tags + ["lolbin"], None

    return Severity.INFO, tags, None


def _snapshot_process(p: psutil.Process) -> Optional[dict]:
    """Build a process snapshot dict."""
    try:
        with p.oneshot():
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                exe = ""
            try:
                cmdline = " ".join(p.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cmdline = ""
            try:
                username = p.username()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                username = ""
            try:
                cwd = p.cwd()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cwd = ""
            try:
                create_ts = datetime.fromtimestamp(
                    p.create_time(), tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            except Exception:
                create_ts = ""

            return {
                "pid":        p.pid,
                "ppid":       p.ppid(),
                "name":       p.name(),
                "exe":        exe,
                "cmdline":    cmdline,
                "username":   username,
                "cwd":        cwd,
                "created_at": create_ts,
                "status":     p.status(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


class ProcessCollector:
    """
    Polls psutil.process_iter() to detect new and exited processes.
    Enriches telemetry directly into flat schema payloads without using sub-objects.
    """

    def __init__(
        self,
        dispatch:          Callable,
        machine_info: dict,
        poll_interval:     float = 1.5,
        resource_interval: float = 30.0,
        hash_executables:  bool  = True,
    ):
        self._dispatch          = dispatch
        self._interval          = poll_interval
        self._resource_interval = resource_interval
        self._hash_exe          = hash_executables
        self._stop              = threading.Event()
        self._known_pids: Dict[int, dict] = {}
        self._threads           = []
        self._exe_hash_cache: Dict[str, str] = {}
        self._machine_info =  machine_info

    def _get_exe_hash(self, exe_path: str) -> Optional[str]:
        if not exe_path or not Path(exe_path).is_file():
            return None
        if exe_path in self._exe_hash_cache:
            return self._exe_hash_cache[exe_path]
        hashes = hash_file(exe_path)
        h = hashes.get("sha256")
        if h:
            self._exe_hash_cache[exe_path] = h
        return h

    def _emit_process_event(self, snap: dict, action: str):
        severity, tags, mitre_tech = _assess_process(
            snap["name"], snap["exe"], snap["cmdline"]
        )

        exe_hash = None
        if self._hash_exe and action == "start":
            exe_hash = self._get_exe_hash(snap["exe"])

        # Try to get parent name for tag context enrichment
        try:
            pp = psutil.Process(snap["ppid"])
            parent_name = pp.name()
            if parent_name:
                tags.append(f"parent:{parent_name}")
        except Exception:
            pass

        # Populate flat event properties natively
        event = ProcessEvent(
            action                = action,
            outcome               = EventOutcome.SUCCESS,
            severity              = severity,
            tags                  = tags,
            mitre_technique       = mitre_tech,
            mitre_tactic          = "Execution" if mitre_tech else None,
            # Assign flattened processing values directly
            process_pid           = snap["pid"],
            process_ppid          = snap["ppid"],
            process_name          = snap["name"],
            process_executable    = snap["exe"],
            process_command_line  = snap["cmdline"],
            process_working_dir   = snap.get("cwd"),
            process_start_time    = snap.get("created_at"),
            process_user          = snap.get("username"),
            process_sha256        = exe_hash,
        )
        self._dispatch(event.to_dict(), self._machine_info)

    def _poll_processes(self):
        print("ProcessCollector polling started")
        while not self._stop.is_set():
            try:
                current_pids: Dict[int, dict] = {}
                for p in psutil.process_iter(attrs=None):
                    snap = _snapshot_process(p)
                    if snap:
                        current_pids[snap["pid"]] = snap

                # New processes
                for pid, snap in current_pids.items():
                    if pid not in self._known_pids:
                        self._emit_process_event(snap, "start")

                # Exited processes
                for pid, snap in self._known_pids.items():
                    if pid not in current_pids:
                        self._emit_process_event(snap, "stop")

                self._known_pids = current_pids

            except Exception as ex:
                print(f"Process poll error: {ex}")
            time.sleep(self._interval)

    def _poll_resources(self):
        """Separately monitor resource usage spikes using flat events."""
        while not self._stop.is_set():
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "username"]):
                    try:
                        cpu = p.cpu_percent(interval=0)
                        mem = p.memory_info().rss / (1024 * 1024)
                        if cpu > HIGH_CPU_THRESHOLD or mem > HIGH_MEMORY_MB:
                            snap = _snapshot_process(p)
                            if not snap:
                                continue
                            severity = Severity.MEDIUM
                            tags = ["process", "resource_spike"]
                            if cpu > 95 or mem > 4096:
                                severity = Severity.HIGH
                                tags.append("potential_cryptominer")

                            event = ProcessEvent(
                                action                = "resource_spike",
                                outcome               = EventOutcome.UNKNOWN,
                                severity              = severity,
                                tags                  = tags,
                                notes                 = f"CPU={cpu:.1f}% MEM={mem:.1f}MB",
                                mitre_technique       = "T1496" if cpu > 90 else None,
                                mitre_tactic          = "Impact" if cpu > 90 else None,
                                # Direct properties mapping
                                process_pid           = snap["pid"],
                                process_name          = snap["name"],
                                process_executable    = snap["exe"],
                                process_user          = snap.get("username"),
                                process_cpu_percent   = cpu,
                                process_memory_rss_mb = mem,
                            )
                            self._dispatch(event.to_dict(), self._machine_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception as ex:
                print(f"Resource poll error: {ex}")
            time.sleep(self._resource_interval)

    def start(self):
        t1 = threading.Thread(target=self._poll_processes, daemon=True, name="proc-lifecycle")
        t2 = threading.Thread(target=self._poll_resources, daemon=True, name="proc-resources")
        self._threads = [t1, t2]
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop.set()