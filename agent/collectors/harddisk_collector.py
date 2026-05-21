"""
Sentinel Agent - Hard Disk / Storage Collector
Monitors internal fixed disks for security-relevant events:
  • Disk almost full (potential DoS / log-flooding attack)
  • New partitions or mount points appearing unexpectedly
  • SMART health degradation (Linux: smartmontools; Windows: WMI)
  • Rapid deletion of large amounts of data (ransomware indicator)
  • Suspicious mount options (noexec removed, setuid allowed, etc.)

Platform support:
  Linux   – psutil + smartmontools (smartctl) + /proc/mounts
  Windows – psutil + WMI (optional)
  macOS   – psutil + diskutil

Requires: psutil  (already in requirements.txt)
Optional: smartmontools installed on host for SMART data
"""

import time
import platform
import threading
import subprocess
import json
from typing import Callable, Dict, Optional, Set, Tuple
from pathlib import Path

import psutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from schema.event_schema import (
    SentinelEvent, FileInfo,
    EventCategory, EventAction, EventOutcome, Severity,
    get_host_info,
)

# ─────────────────────────────────────────────
#  THRESHOLDS & CONSTANTS
# ─────────────────────────────────────────────

DISK_WARN_PERCENT      = 85.0   # warn when used% crosses this
DISK_CRITICAL_PERCENT  = 95.0   # critical when used% crosses this

# Drop in free bytes in one poll cycle that suggests rapid deletion / overwrite
RAPID_FREE_DROP_BYTES  = 1 * 1024 * 1024 * 1024   # 1 GB freed suddenly = potential wipe

# SMART attribute IDs that indicate hardware failure risk
SMART_CRITICAL_ATTRS = {
    "5":   "Reallocated_Sector_Ct",
    "187": "Reported_Uncorrect",
    "188": "Command_Timeout",
    "197": "Current_Pending_Sector",
    "198": "Offline_Uncorrectable",
}

# Mount options that indicate a security configuration change
SECURE_OPTS   = {"noexec", "nosuid", "nodev"}
INSECURE_OPTS = {"exec", "suid", "dev"}   # if these appear where they shouldn't


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _is_fixed_partition(part) -> bool:
    """Return True for internal fixed disks (skip pseudo-fs, tmpfs, removable)."""
    skip_fs = {
        "tmpfs", "devtmpfs", "squashfs", "overlay", "aufs",
        "proc", "sysfs", "cgroup", "cgroup2", "pstore",
        "debugfs", "securityfs", "configfs", "fusectl",
        "efivarfs", "hugetlbfs", "mqueue",
    }
    opts  = part.opts.lower()
    mount = part.mountpoint.lower()

    if part.fstype.lower() in skip_fs:
        return False
    if "removable" in opts:
        return False
    # Skip obvious pseudo-mount points
    for skip in ("/proc", "/sys", "/dev", "/run"):
        if mount.startswith(skip):
            return False
    # Skip macOS disk images / Time Machine volumes
    if platform.system() == "Darwin":
        if "disk image" in opts or mount.startswith("/private/var/folders"):
            return False
    return True


def _disk_snapshot(part) -> Optional[dict]:
    try:
        usage = psutil.disk_usage(part.mountpoint)
        return {
            "device":      part.device,
            "mountpoint":  part.mountpoint,
            "fstype":      part.fstype,
            "opts":        part.opts,
            "total":       usage.total,
            "used":        usage.used,
            "free":        usage.free,
            "percent":     usage.percent,
        }
    except PermissionError:
        return None
    except Exception as exc:
        print(f"disk snapshot error on {part.mountpoint}: {exc}")
        return None


# ── SMART helpers ─────────────────────────────

def _get_block_devices_linux() -> list:
    """Return list of block device paths (e.g. /dev/sda) on Linux."""
    devs = []
    try:
        out = subprocess.check_output(
            ["lsblk", "-dn", "-o", "NAME,TYPE"],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == "disk":
                devs.append(f"/dev/{parts[0]}")
    except Exception:
        pass
    return devs


def _smart_health_linux(device: str) -> Optional[dict]:
    """
    Run smartctl -j (JSON) and extract critical attributes.
    Returns a dict with 'healthy': bool and 'alerts': [str]
    """
    try:
        out = subprocess.check_output(
            ["smartctl", "-j", "-H", "-A", device],
            stderr=subprocess.DEVNULL, timeout=10, text=True,
        )
        data = json.loads(out)
    except FileNotFoundError:
        return None   # smartmontools not installed
    except Exception:
        return None

    alerts = []
    healthy = True

    # Overall SMART health
    smart_status = data.get("smart_status", {})
    if not smart_status.get("passed", True):
        healthy = False
        alerts.append("SMART FAIL: overall health test did not pass")

    # Check critical attributes
    for attr in data.get("ata_smart_attributes", {}).get("table", []):
        attr_id = str(attr.get("id", ""))
        if attr_id in SMART_CRITICAL_ATTRS:
            raw_value = attr.get("raw", {}).get("value", 0)
            if raw_value > 0:
                name = SMART_CRITICAL_ATTRS[attr_id]
                alerts.append(f"{name} (id={attr_id}) raw={raw_value}")
                healthy = False

    return {"healthy": healthy, "alerts": alerts, "device": device}


def _smart_health_macos(device: str) -> Optional[dict]:
    """Use diskutil on macOS for basic health info."""
    try:
        out = subprocess.check_output(
            ["diskutil", "info", device],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        )
        healthy = True
        alerts = []
        for line in out.splitlines():
            if "SMART Status" in line:
                status = line.split(":", 1)[-1].strip()
                if status.lower() != "verified":
                    healthy = False
                    alerts.append(f"SMART Status: {status}")
        return {"healthy": healthy, "alerts": alerts, "device": device}
    except Exception:
        return None


# ─────────────────────────────────────────────
#  COLLECTOR CLASS
# ─────────────────────────────────────────────

class HardDiskCollector:
    """
    Monitors internal fixed storage for security-relevant events.

    Events emitted:
      • disk_space_warning       – disk usage above WARN threshold (MEDIUM)
      • disk_space_critical      – disk usage above CRITICAL threshold (HIGH)
      • disk_partition_new       – unexpected new partition/mount (MEDIUM)
      • disk_partition_removed   – partition disappeared unexpectedly (LOW)
      • disk_smart_failure       – SMART pre-failure attributes detected (HIGH)
      • disk_rapid_free_increase – large free-space jump (possible mass delete / ransomware wipe) (HIGH)
      • disk_mount_opts_changed  – security-relevant mount options changed (MEDIUM)
    """

    def __init__(
        self,
        dispatch: Callable[[dict], None],
        machine_info: dict,
        poll_interval: float = 30.0,
        smart_interval: float = 300.0,     # check SMART every 5 minutes
        warn_percent: float   = DISK_WARN_PERCENT,
        critical_percent: float = DISK_CRITICAL_PERCENT,
        enable_smart: bool    = True,
    ):
        self._dispatch          = dispatch
        self._interval          = poll_interval
        self._smart_interval    = smart_interval
        self._warn_pct          = warn_percent
        self._crit_pct          = critical_percent
        self._enable_smart      = enable_smart

        self._stop    = threading.Event()
        self._threads: list = []

        # State: mountpoint -> snapshot dict
        self._known: Dict[str, dict] = {}
        # Track which mounts have already fired a space warning (avoid spam)
        self._warned: Set[str] = set()
        self._machine_info =  machine_info

    # ── event builder ────────────────────────

    def _emit(
        self,
        action: str,
        snap: dict,
        severity: str = Severity.INFO,
        outcome: str  = EventOutcome.SUCCESS,
        tags: list    = None,
        notes: str    = None,
    ):
        file_info = FileInfo(
            path      = snap.get("mountpoint", snap.get("device", "")),
            name      = Path(snap.get("mountpoint", snap.get("device", ""))).name or "/",
            directory = snap.get("mountpoint", snap.get("device", "")),
        )
        event = SentinelEvent(
            category  = EventCategory.FILE,
            action    = action,
            outcome   = outcome,
            severity  = severity,
            collector = "harddisk_monitor",
            host      = get_host_info(),
            file      = file_info,
            tags      = (tags or []) + ["disk", "storage"],
            notes     = notes or (
                f"device={snap.get('device')} mount={snap.get('mountpoint')} "
                f"used={snap.get('percent', '?')}%"
            ),
        )
        self._dispatch(event.to_dict() , self._machine_info)

    # ── checks ───────────────────────────────

    def _check_space(self, snap: dict):
        mp   = snap["mountpoint"]
        pct  = snap["percent"]

        if pct >= self._crit_pct:
            if f"{mp}:critical" not in self._warned:
                self._warned.add(f"{mp}:critical")
                self._warned.discard(f"{mp}:warn")
                free_mb = snap["free"] / (1024 * 1024)
                self._emit(
                    "disk_space_critical", snap,
                    severity = Severity.HIGH,
                    outcome  = EventOutcome.FAILURE,
                    tags     = ["disk_full", "disk_space_critical"],
                    notes    = (
                        f"Disk critically full: {pct:.1f}% used on {mp} "
                        f"({free_mb:.0f} MB free) — potential DoS or log-flood risk"
                    ),
                )
                print(f"Disk CRITICAL on {mp}: {pct:.1f}% used")

        elif pct >= self._warn_pct:
            if f"{mp}:warn" not in self._warned:
                self._warned.add(f"{mp}:warn")
                free_gb = snap["free"] / (1024 ** 3)
                self._emit(
                    "disk_space_warning", snap,
                    severity = Severity.MEDIUM,
                    tags     = ["disk_space_warning"],
                    notes    = (
                        f"Disk usage high: {pct:.1f}% used on {mp} "
                        f"({free_gb:.1f} GB free)"
                    ),
                )
                print(f"Disk WARN on {mp}: {pct:.1f}% used")
        else:
            # Usage dropped back below warn threshold – reset so future alerts fire
            self._warned.discard(f"{mp}:warn")
            self._warned.discard(f"{mp}:critical")

    def _check_rapid_free(self, snap: dict, prev: dict):
        """Detect sudden large increase in free space — mass delete or ransomware wipe."""
        delta_free = snap["free"] - prev["free"]
        if delta_free >= RAPID_FREE_DROP_BYTES:
            gb = delta_free / (1024 ** 3)
            self._emit(
                "disk_rapid_free_increase", snap,
                severity = Severity.HIGH,
                outcome  = EventOutcome.UNKNOWN,
                tags     = ["mass_delete", "ransomware_indicator", "data_loss_risk"],
                notes    = (
                    f"Free space on {snap['mountpoint']} increased by {gb:.2f} GB "
                    f"in one poll cycle — possible mass file deletion or ransomware wipe"
                ),
            )
            print(
                f"Rapid free-space increase on {snap['mountpoint']}: {gb:.2f} GB freed"
            )

    def _check_mount_opts_changed(self, snap: dict, prev: dict):
        """Alert if security-relevant mount options changed between polls."""
        old_opts = set(prev["opts"].lower().split(","))
        new_opts = set(snap["opts"].lower().split(","))

        added   = new_opts - old_opts
        removed = old_opts - new_opts

        added_insecure   = added   & INSECURE_OPTS
        removed_secure   = removed & SECURE_OPTS

        if added_insecure or removed_secure:
            self._emit(
                "disk_mount_opts_changed", snap,
                severity = Severity.MEDIUM,
                outcome  = EventOutcome.UNKNOWN,
                tags     = ["mount_opts_changed", "security_config"],
                notes    = (
                    f"Mount option change on {snap['mountpoint']}: "
                    f"added={added_insecure or added} removed={removed_secure or removed}"
                ),
            )
            print(f"Mount opts changed on {snap['mountpoint']}")

    # ── SMART polling ────────────────────────

    def _poll_smart(self):
        print("HardDiskCollector SMART polling started")
        os_name = platform.system()

        while not self._stop.is_set():
            try:
                if os_name == "Linux":
                    for dev in _get_block_devices_linux():
                        result = _smart_health_linux(dev)
                        if result and not result["healthy"]:
                            snap = {"device": dev, "mountpoint": dev}
                            self._emit(
                                "disk_smart_failure", snap,
                                severity = Severity.HIGH,
                                outcome  = EventOutcome.FAILURE,
                                tags     = ["smart_failure", "hardware_failure_risk"],
                                notes    = (
                                    f"SMART pre-failure indicators on {dev}: "
                                    + "; ".join(result["alerts"])
                                ),
                            )
                            print(f"SMART failure on {dev}: {result['alerts']}")

                elif os_name == "Darwin":
                    # Check the primary disk only (/dev/disk0)
                    result = _smart_health_macos("/dev/disk0")
                    if result and not result["healthy"]:
                        snap = {"device": "/dev/disk0", "mountpoint": "/"}
                        self._emit(
                            "disk_smart_failure", snap,
                            severity = Severity.HIGH,
                            outcome  = EventOutcome.FAILURE,
                            tags     = ["smart_failure", "hardware_failure_risk"],
                            notes    = "; ".join(result["alerts"]),
                        )

                # Windows SMART via WMI (optional – not imported at module level)
                elif os_name == "Windows":
                    try:
                        import wmi
                        c = wmi.WMI()
                        for disk in c.Win32_DiskDrive():
                            status = disk.Status or ""
                            if status.lower() not in ("ok", ""):
                                snap = {"device": disk.DeviceID, "mountpoint": disk.DeviceID}
                                self._emit(
                                    "disk_smart_failure", snap,
                                    severity = Severity.HIGH,
                                    outcome  = EventOutcome.FAILURE,
                                    tags     = ["smart_failure", "hardware_failure_risk"],
                                    notes    = f"WMI disk status={status} on {disk.DeviceID}",
                                )
                    except ImportError:
                        pass   # wmi not installed – skip silently

            except Exception as exc:
                print(f"SMART poll error: {exc}")

            self._stop.wait(self._smart_interval)

    # ── main polling loop ────────────────────

    def _poll(self):
        print("HardDiskCollector disk-space polling started")

        # Seed initial state silently
        try:
            for part in psutil.disk_partitions(all=False):
                if _is_fixed_partition(part):
                    snap = _disk_snapshot(part)
                    if snap:
                        self._known[part.mountpoint] = snap
            print(
                f"HardDiskCollector seeded {len(self._known)} partition(s): "
                + ", ".join(self._known.keys())
            )
        except Exception as exc:
            print(f"Disk seed error: {exc}")

        while not self._stop.is_set():
            try:
                current: Dict[str, dict] = {}
                for part in psutil.disk_partitions(all=False):
                    if not _is_fixed_partition(part):
                        continue
                    snap = _disk_snapshot(part)
                    if snap:
                        current[part.mountpoint] = snap

                # New partitions
                for mp, snap in current.items():
                    if mp not in self._known:
                        print(f"New partition appeared: {snap['device']} → {mp}")
                        self._emit(
                            "disk_partition_new", snap,
                            severity = Severity.MEDIUM,
                            tags     = ["new_partition", "unexpected_mount"],
                            notes    = (
                                f"New partition mounted: {snap['device']} → {mp} "
                                f"(fs={snap['fstype']}, opts={snap['opts']})"
                            ),
                        )

                # Removed partitions
                for mp, snap in self._known.items():
                    if mp not in current:
                        print(f"Partition disappeared: {snap['device']} ← {mp}")
                        self._emit(
                            "disk_partition_removed", snap,
                            severity = Severity.LOW,
                            tags     = ["partition_removed"],
                            notes    = f"Partition unmounted: {snap['device']} ← {mp}",
                        )

                # Per-partition checks for existing partitions
                for mp, snap in current.items():
                    self._check_space(snap)
                    if mp in self._known:
                        self._check_rapid_free(snap, self._known[mp])
                        self._check_mount_opts_changed(snap, self._known[mp])

                self._known = current

            except Exception as exc:
                print(f"Disk poll error: {exc}")

            time.sleep(self._interval)

    # ── lifecycle ────────────────────────────

    def start(self):
        t1 = threading.Thread(target=self._poll,       daemon=True, name="disk-space")
        t2 = threading.Thread(target=self._poll_smart, daemon=True, name="disk-smart")
        self._threads = [t1]
        t1.start()
        if self._enable_smart and platform.system() in ("Linux", "Darwin", "Windows"):
            self._threads.append(t2)
            t2.start()

    def stop(self):
        self._stop.set()
