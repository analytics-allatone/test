"""
Sentinel Agent - File System Collector
Monitors file CRUD operations using watchdog (cross-platform).
Captures: create, modify, delete, rename, chmod, chown
Hashes: SHA256, SHA1, MD5 for every file touched.
"""

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
from schema.event_schema import (
    SentinelEvent, FileInfo, UserInfo, ProcessInfo,
    EventCategory, EventAction, EventOutcome, Severity,
    hash_file, get_host_info
)

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _get_file_info(path: str, old_path: str = None, old_sha256: str = None) -> FileInfo:
    p = Path(path)
    info = FileInfo(
        path      = str(p.resolve()),
        name      = p.name,
        extension = p.suffix.lower(),
        directory = str(p.parent),
        old_path  = old_path,
        old_sha256= old_sha256,
    )
    try:
        st = p.stat()
        info.size_bytes  = st.st_size
        info.inode       = st.st_ino if platform.system() != "Windows" else None
        info.modified_at = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        info.created_at  = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
        # Permissions
        mode = stat.filemode(st.st_mode)
        info.permissions = mode
        if platform.system() != "Windows":
            import pwd, grp
            try:
                info.owner = pwd.getpwuid(st.st_uid).pw_name
                info.group = grp.getgrgid(st.st_gid).gr_name
            except Exception:
                info.owner = str(st.st_uid)
                info.group = str(st.st_gid)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    if p.is_file():
        hashes = hash_file(str(p))
        info.sha256 = hashes["sha256"]
        info.sha1   = hashes["sha1"]
        info.md5    = hashes["md5"]

    return info


def _get_current_user() -> UserInfo:
    user = UserInfo()
    try:
        if platform.system() != "Windows":
            import pwd
            pw = pwd.getpwuid(os.getuid())
            user.name          = pw.pw_name
            user.uid           = os.getuid()
            user.gid           = os.getgid()
            user.effective_uid = os.geteuid()
            user.effective_gid = os.getegid()
            user.home_dir      = pw.pw_dir
            user.shell         = pw.pw_shell
        else:
            import getpass
            user.name = getpass.getuser()
    except Exception:
        pass
    return user


def _severity_for_path(path: str) -> str:
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
    def __init__(self, dispatch: Callable,machine_info ,  ignore_dirs: List[str] = None):
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

    def _emit(self, action: str, src_path: str, dst_path: str = None):
        if self._is_ignored(src_path):
            return

        old_sha = self._hash_cache.get(src_path)

        file_info = _get_file_info(
            src_path,
            old_path  = dst_path if action == EventAction.RENAME else None,
            old_sha256= old_sha  if action == EventAction.UPDATE else None,
        )

        # Cache new hash
        if file_info.sha256:
            self._hash_cache[src_path] = file_info.sha256

        # Skip modify events where hash didn't change (metadata-only touch)
        if action == EventAction.UPDATE and old_sha and old_sha == file_info.sha256:
            return

        event = SentinelEvent(
            category   = EventCategory.FILE,
            action     = action,
            outcome    = EventOutcome.SUCCESS,
            severity   = _severity_for_path(src_path),
            collector  = "file_watcher",
            host       = get_host_info(),
            file       = file_info,
            user       = _get_current_user(),
            tags       = ["filesystem"],
        )
        self._dispatch(event.to_dict() , self.machine_info)

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
    Uses watchdog's native inotify (Linux) / FSEvents (macOS) / ReadDirectoryChanges (Windows).
    Falls back to polling if native backend unavailable.
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
        handler  = SentinelFileHandler(self._dispatch,self._machine_info, self._ignore_dirs)
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
