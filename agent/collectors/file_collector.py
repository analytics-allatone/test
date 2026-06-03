import os
import stat
import time
import platform
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Callable

try:
    from watchdog.observers import Observer
    from watchdog.observers.polling import PollingObserver
    from watchdog.events import (
        FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent,
        FileModifiedEvent, FileMovedEvent, DirCreatedEvent,
        DirDeletedEvent, DirModifiedEvent, DirMovedEvent
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the new flat file schema components
from schema.file_schema import FileEvent, EventCategory, EventOutcome, Severity, EventAction
from schema.event_schema import hash_file  # Retaining metadata extraction dependency

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _populate_file_fields(event_obj: FileEvent, path: str, old_path: str = None, old_sha256: str = None):
    """Enriches the FileEvent instance with file-level attributes directly."""
    p = Path(path)
    event_obj.file_path = str(p.resolve())
    event_obj.file_name = p.name
    event_obj.file_extension = p.suffix.lower()
    event_obj.file_directory = str(p.parent)
    event_obj.file_old_path = old_path
    event_obj.file_old_sha256 = old_sha256

    try:
        st = p.stat()
        event_obj.file_size_bytes = st.st_size
        event_obj.file_inode = st.st_ino if platform.system() != "Windows" else None
        event_obj.file_modified_at = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        event_obj.file_created_at = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
        
        # Permissions
        mode = stat.filemode(st.st_mode)
        event_obj.file_permissions = mode
        if platform.system() != "Windows":
            import pwd, grp
            try:
                event_obj.file_owner = pwd.getpwuid(st.st_uid).pw_name
                event_obj.file_group = grp.getgrgid(st.st_gid).gr_name
            except Exception:
                event_obj.file_owner = str(st.st_uid)
                event_obj.file_group = str(st.st_gid)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    if p.is_file():
        hashes = hash_file(str(p))
        event_obj.file_sha256 = hashes["sha256"]
        event_obj.file_sha1 = hashes["sha1"]
        event_obj.file_md5 = hashes["md5"]


def _populate_user_fields(event_obj: FileEvent):
    """Enriches the FileEvent instance with user metrics directly."""
    try:
        if platform.system() != "Windows":
            import pwd
            pw = pwd.getpwuid(os.getuid())
            event_obj.user_name = pw.pw_name
            event_obj.user_uid = os.getuid()
            event_obj.user_gid = os.getgid()
            event_obj.user_effective_uid = os.geteuid()
            event_obj.user_effective_gid = os.getegid()
            event_obj.user_home_dir = pw.pw_dir
            event_obj.user_shell = pw.pw_shell
        else:
            import getpass
            event_obj.user_name = getpass.getuser()
    except Exception:
        pass


def _severity_for_path(path: str) -> Severity:
    """Assign severity based on path sensitivity."""
    path_lower = path.lower()
    critical_patterns = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "c:\\windows\\system32", "/boot/", "/usr/bin/",
        "/.ssh/", ".bashrc", ".bash_profile", ".profile",
        "c:\\users\\administrator", "/root/",
    ]
    high_patterns = [
        "/etc/", "/usr/", "/bin/", "/sbin/",
        "c:\\windows\\", "c:\\program files\\",
        ".env", "id_rsa", "authorized_keys",
    ]
    for pat in critical_patterns:
        if pat in path_lower:
            return Severity.CRITICAL
    for pat in high_patterns:
        if pat in path_lower:
            return Severity.HIGH
    return Severity.INFO


# ─────────────────────────────────────────────
#  WATCHDOG HANDLER
# ─────────────────────────────────────────────

class SentinelFileHandler(FileSystemEventHandler):
    def __init__(self, dispatch: Callable, machine_info, ignore_dirs: List[str] = None):
        super().__init__()
        self._dispatch    = dispatch
        self.machine_info = machine_info
        self._ignore_dirs = [Path(d).resolve() for d in (ignore_dirs or [])]
        self._hash_cache  = {}  # path → sha256, for detecting actual content changes

    def _is_ignored(self, path: str) -> bool:
        try:
            p = Path(path).resolve()
            return any(p.is_relative_to(ig) for ig in self._ignore_dirs)
        except Exception:
            return False

    def _emit(self, action: EventAction, src_path: str, dst_path: str = None):
        if self._is_ignored(src_path):
            return

        old_sha = self._hash_cache.get(src_path)

        # Base structural initialization
        event = FileEvent(
            action=action,
            outcome=EventOutcome.SUCCESS,
            severity=_severity_for_path(src_path),
            tags=["filesystem"],
        )

        # Direct attribution populations without sub-object allocations
        _populate_file_fields(
            event, 
            src_path, 
            old_path=dst_path if action == EventAction.RENAME else None,
            old_sha256=old_sha if action == EventAction.UPDATE else None
        )
        _populate_user_fields(event)

        # Cache new hash
        if event.file_sha256:
            self._hash_cache[src_path] = event.file_sha256

        # Skip modify events where hash didn't change (metadata-only touch)
        if action == EventAction.UPDATE and old_sha and old_sha == event.file_sha256:
            return
        self._dispatch(event.to_dict(), self.machine_info)

    def on_created(self, event):
        if not event.is_directory:
            self._emit(EventAction.CREATE, event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._hash_cache.pop(event.src_path, None)
            self._emit(EventAction.DELETE, event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit(EventAction.UPDATE, event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit(EventAction.RENAME, event.src_path, event.dest_path)


# ─────────────────────────────────────────────
#  COLLECTOR CLASS
# ─────────────────────────────────────────────

class FileCollector:
    """
    Watches one or more directories for file system changes.
    Uses watchdog's native engine, passing telemetry up through structural flat models.
    """

    def __init__(
        self,
        dispatch:    Callable,
        machine_info: dict,
        watch_paths: List[str] = None,
        ignore_dirs: List[str] = None,
        recursive:   bool      = True,
        use_polling: bool      = False,
    ):
        if not WATCHDOG_AVAILABLE:
            raise ImportError("watchdog not installed. Run: pip install watchdog")

        self._dispatch    = dispatch
        self._watch_paths = watch_paths or self._default_paths()
        self._ignore_dirs = ignore_dirs or self._default_ignores()
        self._recursive   = recursive
        self._observer    = None
        self._use_polling = use_polling
        self._machine_info =  machine_info

        print(f"FileCollector watching: {self._watch_paths}")

    @staticmethod
    def _default_paths() -> List[str]:
        if platform.system() == "Windows":
            return ["C:\\Users", "C:\\Windows\\System32", "C:\\ProgramData"]
        return ["/etc", "/home", "/root", "/tmp", "/var/log", "/usr/bin", "/usr/sbin"]

    @staticmethod
    def _default_ignores() -> List[str]:
        if platform.system() == "Windows":
            return ["C:\\Windows\\Temp"]
        return ["/proc", "/sys", "/dev", "/run"]

    def start(self):
        handler  = SentinelFileHandler(self._dispatch, self._machine_info, self._ignore_dirs)
        ObsClass = PollingObserver if self._use_polling else Observer
        self._observer = ObsClass()
        for path in self._watch_paths:
            if Path(path).exists():
                self._observer.schedule(handler, path, recursive=self._recursive)
                print(f"Watching {path}")
            else:
                print(f"Path not found, skipping: {path}")
        self._observer.start()
        print("FileCollector started")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
        print("FileCollector stopped")
