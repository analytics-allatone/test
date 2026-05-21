"""
Sentinel Agent - USB / Pendrive Collector  (v2 - full rewrite)
==============================================================
Detects ALL removable USB storage devices across Linux, Windows, macOS.

What is detected
----------------
  usb_connected       – any new removable partition mounts (FAT32, NTFS, exFAT,
                         ext4, HFS+, APFS, UDF, ISO9660, F2FS …)
  usb_disconnected    – device removed / safely ejected
  usb_raw_device      – Linux: USB block device visible in /sys but NOT yet mounted
  usb_autorun_found   – autorun.inf / executable files found at drive root
  usb_data_transfer   – large write detected (data exfiltration indicator)

Fixes over v1
-------------
  • All psutil.disk_partitions(all=True)  → catches every fs type incl. NTFS/exFAT
  • Linux /sys/bus/usb/devices scan       → catches unmounted raw USB devices
  • Windows: all drive letters A-Z checked, not just D/E/F
  • macOS: /Volumes + diskutil serial / vendor info
  • usb_disconnected uses a safe copy of snap, never touches live mountpoint
  • lsblk called with device path, not mountpoint
  • Vendor / Product / Serial captured where possible (forensic metadata)
  • Graceful fallback on every platform – never crashes the poll loop
"""

import os
import re
import time
import platform
import threading
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import psutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from schema.event_schema import (
    SentinelEvent, FileInfo,
    EventCategory, EventOutcome, Severity,
    get_host_info,
)


OS = platform.system()   # "Linux" | "Windows" | "Darwin"

# ──────────────────────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────────────────────

SUSPICIOUS_LABELS: Set[str] = {
    "rubber ducky", "hak5", "bashbunny", "malware", "payload",
    "autorun", "hack", "exploit", "pentest", "badusb", "pwnagotchi",
}

AUTORUN_FILES: Set[str] = {
    "autorun.inf", "autorun.bat", "autorun.exe",
    "launch.bat", "start.bat", "run.exe", ".autorun",
}

EXECUTABLE_EXTS: Set[str] = {
    # Windows
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".scr", ".pif", ".com", ".lnk", ".msi", ".wsf",
    # Linux / macOS
    ".sh", ".py", ".pl", ".rb", ".elf", ".bin",
    ".dmg", ".pkg", ".app",
}

# Filesystem types that are always removable USB media
REMOVABLE_FS: Set[str] = {
    "fat", "fat16", "fat32", "vfat", "exfat",
    "ntfs", "ntfs-3g",
    "hfs", "hfs+", "hfsplus", "apfs",
    "udf", "iso9660",
    "f2fs", "ext2", "ext3", "ext4",   # Linux formatted pendrives
}

# Filesystem types that are NEVER removable storage
SKIP_FS: Set[str] = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "aufs",
    "proc", "sysfs", "cgroup", "cgroup2", "pstore",
    "debugfs", "securityfs", "configfs", "fusectl",
    "efivarfs", "hugetlbfs", "mqueue", "devfs",
    "autofs", "binfmt_misc", "tracefs",
}

LARGE_TRANSFER_BYTES = 500 * 1024 * 1024   # 500 MB


# ──────────────────────────────────────────────────────────────
#  PLATFORM-SPECIFIC HELPERS
# ──────────────────────────────────────────────────────────────

# ── Linux ────────────────────────────────────────────────────

def _linux_removable_flag(device: str) -> bool:
    """
    Check /sys/block/<dev>/removable == '1'.
    Works for sdb, sdc, sdd … sdz, sda[1-9], nvme external, etc.
    """
    try:
        # Strip partition suffix: /dev/sdb1 → sdb
        base = re.sub(r'\d+$', '', Path(device).name)
        flag = Path(f"/sys/block/{base}/removable").read_text().strip()
        return flag == "1"
    except Exception:
        return False


def _linux_usb_raw_devices() -> List[dict]:
    """
    Walk /sys/bus/usb/devices and find USB mass-storage devices
    (bInterfaceClass == 08) that may or may not be mounted.
    Returns list of {vendor, product, serial, syspath}.
    """
    results = []
    base = Path("/sys/bus/usb/devices")
    if not base.exists():
        return results

    def _read(p: Path) -> str:
        try:
            return p.read_text().strip()
        except Exception:
            return ""

    for dev_path in base.iterdir():
        # Each interface subfolder ends with :<config>.<iface>
        for iface_path in dev_path.glob("*:*"):
            if _read(iface_path / "bInterfaceClass") == "08":   # Mass Storage
                entry = {
                    "vendor":   _read(dev_path / "idVendor"),
                    "product":  _read(dev_path / "idProduct"),
                    "serial":   _read(dev_path / "serial"),
                    "mfr":      _read(dev_path / "manufacturer"),
                    "prod_name":_read(dev_path / "product"),
                    "syspath":  str(dev_path),
                }
                results.append(entry)
                break   # one entry per physical device
    return results


def _linux_device_info(device: str) -> dict:
    """Use lsblk to get label, serial, model for a block device."""
    info = {"label": "", "serial": "", "model": "", "size_bytes": 0}
    try:
        out = subprocess.check_output(
            ["lsblk", "-ndo", "LABEL,SERIAL,MODEL,SIZE", device],
            stderr=subprocess.DEVNULL, timeout=4, text=True,
        ).strip()
        parts = out.split(None, 3)
        if len(parts) >= 1: info["label"]  = parts[0] if parts[0] != "" else ""
        if len(parts) >= 2: info["serial"] = parts[1]
        if len(parts) >= 3: info["model"]  = parts[2]
    except Exception:
        pass
    # Also try udevadm for richer data
    try:
        out = subprocess.check_output(
            ["udevadm", "info", "--query=property", f"--name={device}"],
            stderr=subprocess.DEVNULL, timeout=4, text=True,
        )
        for line in out.splitlines():
            k, _, v = line.partition("=")
            if k == "ID_FS_LABEL":   info["label"]  = v
            if k == "ID_SERIAL":     info["serial"] = v
            if k == "ID_MODEL":      info["model"]  = v
            if k == "ID_VENDOR":     info.setdefault("vendor", v)
    except Exception:
        pass
    return info


# ── Windows ──────────────────────────────────────────────────

def _windows_removable_drives() -> List[dict]:
    """
    Use psutil + win32api (if available) to enumerate all removable drives.
    Falls back to pure psutil if win32api absent.
    """
    drives = []
    try:
        import win32api, win32con  # type: ignore
        drive_bits = win32api.GetLogicalDrives()
        for i in range(26):
            if drive_bits & (1 << i):
                letter = chr(65 + i) + ":\\"
                try:
                    dtype = win32api.GetDriveType(letter)
                    # DRIVE_REMOVABLE = 2, DRIVE_CDROM = 5
                    if dtype == 2:
                        vol_info = ("", "", "")
                        try:
                            vol_info = win32api.GetVolumeInformation(letter)
                        except Exception:
                            pass
                        drives.append({
                            "mountpoint": letter,
                            "label": vol_info[0],
                            "serial_num": hex(vol_info[1]) if vol_info[1] else "",
                            "fstype": vol_info[4] if len(vol_info) > 4 else "",
                        })
                except Exception:
                    pass
    except ImportError:
        # Fallback: psutil only
        for part in psutil.disk_partitions(all=True):
            opts = part.opts.lower()
            if "removable" in opts or "cdrom" in opts:
                drives.append({
                    "mountpoint": part.mountpoint,
                    "label": "",
                    "serial_num": "",
                    "fstype": part.fstype,
                })
    return drives


# ── macOS ─────────────────────────────────────────────────────

def _macos_disk_info(mountpoint: str) -> dict:
    """diskutil info gives us label, kind, removable flag."""
    info = {"label": "", "kind": "", "removable": False, "protocol": ""}
    try:
        out = subprocess.check_output(
            ["diskutil", "info", mountpoint],
            stderr=subprocess.DEVNULL, timeout=6, text=True,
        )
        for line in out.splitlines():
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if "volume name"         in k: info["label"]     = v
            if "type (bundle)"       in k: info["kind"]      = v
            if "removable media"     in k: info["removable"] = v.lower() == "yes"
            if "protocol"            in k: info["protocol"]  = v
    except Exception:
        pass
    return info


# ──────────────────────────────────────────────────────────────
#  PARTITION FILTER  (the critical fix)
# ──────────────────────────────────────────────────────────────

def _is_removable_partition(part) -> bool:
    """
    Comprehensive removable-media check for all three platforms.
    Uses ALL=True partitions so exFAT/NTFS pendrives are not filtered out.
    """
    fs   = part.fstype.lower()
    opts = part.opts.lower()
    mp   = part.mountpoint

    # Always skip virtual / kernel filesystems
    if fs in SKIP_FS:
        return False
    # Skip zero-length mount-points
    if not mp:
        return False

    if OS == "Linux":
        mp_l = mp.lower()
        # Standard automount locations
        if mp_l.startswith("/media/") or mp_l.startswith("/run/media/"):
            return True
        # /mnt/<anything> that has a removable block device behind it
        if mp_l.startswith("/mnt/"):
            dev = part.device
            if _linux_removable_flag(dev):
                return True
        # Any filesystem type typical of pendrives on any mountpoint
        if fs in REMOVABLE_FS and _linux_removable_flag(part.device):
            return True
        return False

    if OS == "Windows":
        # psutil marks them "removable" in opts when all=True
        if "removable" in opts:
            return True
        # Fallback: drive letter heuristic (psutil sometimes misses the flag)
        if len(mp) >= 2 and mp[1] == ":" and mp[0].upper() not in ("C",):
            if fs.lower() in REMOVABLE_FS:
                return True
        return False

    if OS == "Darwin":
        mp_l = mp.lower()
        # External volumes under /Volumes (excluding the boot volume)
        if mp_l.startswith("/volumes/") and "macintosh hd" not in mp_l:
            info = _macos_disk_info(mp)
            # Accept if diskutil says removable, or protocol is USB/Thunderbolt
            if info["removable"] or "usb" in info["protocol"].lower():
                return True
            # Treat all /Volumes that aren't the system drive as potentially removable
            # (catches exFAT/FAT32/NTFS drives even if diskutil is slow)
            if fs in REMOVABLE_FS:
                return True
        return False

    return False


# ──────────────────────────────────────────────────────────────
#  SNAPSHOT
# ──────────────────────────────────────────────────────────────

def _build_snapshot(part) -> dict:
    """Build a full device snapshot at connect time."""
    mp  = part.mountpoint
    dev = part.device

    snap = {
        "device":     dev,
        "mountpoint": mp,
        "fstype":     part.fstype,
        "opts":       part.opts,
        "label":      "",
        "vendor":     "",
        "model":      "",
        "serial":     "",
        "size_bytes": 0,
        "used_bytes": None,
    }

    # Enrich with platform-specific metadata
    try:
        if OS == "Linux":
            info = _linux_device_info(dev)
            snap["label"]  = info.get("label", "")
            snap["serial"] = info.get("serial", "")
            snap["model"]  = info.get("model", "")

        elif OS == "Darwin":
            info = _macos_disk_info(mp)
            snap["label"]  = info.get("label", "")
            snap["vendor"] = info.get("protocol", "")

        elif OS == "Windows":
            # Try win32api for volume label
            try:
                import win32api  # type: ignore
                vol = win32api.GetVolumeInformation(mp)
                snap["label"]  = vol[0]
                snap["serial"] = hex(vol[1]) if vol[1] else ""
                snap["fstype"] = vol[4] if len(vol) > 4 else part.fstype
            except Exception:
                pass
    except Exception as e:
        print(f"Snapshot enrichment error on {mp}: {e}")

    # Disk usage
    try:
        usage = psutil.disk_usage(mp)
        snap["used_bytes"] = usage.used
        snap["size_bytes"] = usage.total
    except Exception:
        pass

    return snap


# ──────────────────────────────────────────────────────────────
#  SCAN HELPERS
# ──────────────────────────────────────────────────────────────

def _scan_autorun_files(mountpoint: str) -> List[str]:
    found = []
    try:
        root = Path(mountpoint)
        for child in root.iterdir():
            n = child.name.lower()
            if n in AUTORUN_FILES:
                found.append(child.name)
            elif child.is_file() and Path(n).suffix in EXECUTABLE_EXTS:
                found.append(child.name)
    except PermissionError:
        pass
    except Exception as e:
        print(f"Autorun scan error on {mountpoint}: {e}")
    return found


# ──────────────────────────────────────────────────────────────
#  COLLECTOR CLASS
# ──────────────────────────────────────────────────────────────

class USBCollector:
    """
    Polls psutil.disk_partitions(all=True) every `poll_interval` seconds.
    On Linux also watches /sys/bus/usb for raw (unmounted) mass-storage devices.

    Events emitted
    --------------
    usb_connected      LOW / HIGH   – pendrive plugged in (HIGH if suspicious label)
    usb_disconnected   LOW          – pendrive removed / ejected
    usb_raw_device     MEDIUM       – Linux: USB mass-storage seen but not mounted
    usb_autorun_found  HIGH/CRITICAL– suspicious files at drive root
    usb_data_transfer  MEDIUM/HIGH  – large write (exfiltration indicator)
    """

    def __init__(
        self,
        dispatch: Callable[[dict], None],
        machine_info: dict,
        poll_interval: float = 3.0,
        scan_on_connect: bool = True,
        transfer_threshold_bytes: int = LARGE_TRANSFER_BYTES,
    ):
        self._dispatch   = dispatch
        self._interval   = poll_interval
        self._scan       = scan_on_connect
        self._xfer_limit = transfer_threshold_bytes
        self._stop       = threading.Event()
        self._threads: List[threading.Thread] = []

        # mountpoint → snapshot
        self._known: Dict[str, dict] = {}
        # Linux raw USB: syspath → entry dict
        self._known_raw: Dict[str, dict] = {}

        self._machine_info = machine_info

    # ── emit ─────────────────────────────────

    def _emit(
        self,
        action: str,
        snap: dict,
        severity: str = Severity.LOW,
        outcome: str  = EventOutcome.SUCCESS,
        tags: List[str] = None,
        notes: str = None,
    ):
        mp    = snap.get("mountpoint", snap.get("device", "unknown"))
        label = snap.get("label") or Path(mp).name or mp

        # Build a static FileInfo — safe even after device is removed
        file_info = FileInfo(
            path      = mp,
            name      = label,
            directory = mp,
        )

        auto_notes = (
            f"device={snap.get('device','')}  "
            f"fs={snap.get('fstype','')}  "
            f"label='{snap.get('label','')}'"
        )
        if snap.get("serial"):
            auto_notes += f"  serial={snap['serial']}"
        if snap.get("model"):
            auto_notes += f"  model={snap['model']}"
        size_gb = snap.get("size_bytes", 0) / (1024 ** 3)
        if size_gb > 0:
            auto_notes += f"  size={size_gb:.1f}GB"

        event = SentinelEvent(
            category  = EventCategory.FILE,
            action    = action,
            outcome   = outcome,
            severity  = severity,
            collector = "usb_monitor",
            host      = get_host_info(),
            file      = file_info,
            tags      = (tags or []) + ["usb", "removable_media"],
            notes     = notes or auto_notes,
        )
        self._dispatch(event.to_dict() , self._machine_info)

    # ── threat checks ────────────────────────

    def _check_connect(self, snap: dict):
        mp    = snap["mountpoint"]
        label = (snap.get("label") or "").lower()
        tags  = ["usb_connected"]

        if any(bad in label for bad in SUSPICIOUS_LABELS):
            tags.append("suspicious_label")
            self._emit(
                "usb_connected", snap,
                severity = Severity.HIGH,
                tags     = tags,
                notes    = f"Suspicious USB label detected: '{snap.get('label')}' on {mp}",
            )
            print(f"Suspicious USB label '{snap.get('label')}' on {mp}")
        else:
            self._emit("usb_connected", snap, severity=Severity.LOW, tags=tags)
            print(
                f"USB connected: {snap.get('device')} → {mp}  "
                f"[{snap.get('fstype')}]  label='{snap.get('label')}'  "
                f"serial={snap.get('serial')}  size={snap.get('size_bytes',0)//1048576}MB"
            )

        if self._scan:
            bad = _scan_autorun_files(mp)
            if bad:
                sev = Severity.CRITICAL if any(
                    f.lower() in AUTORUN_FILES for f in bad
                ) else Severity.HIGH
                self._emit(
                    "usb_autorun_found", snap,
                    severity = sev,
                    outcome  = EventOutcome.UNKNOWN,
                    tags     = ["usb", "autorun", "potential_malware"],
                    notes    = f"Suspicious files at USB root on {mp}: {bad}",
                )
                print(f"USB autorun files on {mp}: {bad}")

    def _check_disconnect(self, snap: dict):
        """
        Emit removal event using the saved snapshot.
        Never touches the filesystem — the device is already gone.
        """
        mp = snap.get("mountpoint", "unknown")
        self._emit(
            "usb_disconnected", snap,
            severity = Severity.LOW,
            tags     = ["usb_disconnected"],
            notes    = (
                f"USB removed: device={snap.get('device','')}  "
                f"was mounted at {mp}  "
                f"label='{snap.get('label','')}'"
                + (f"  serial={snap['serial']}" if snap.get("serial") else "")
                + (f"  model={snap['model']}"   if snap.get("model")  else "")
            ),
        )
        print(
            f"USB disconnected: {snap.get('device')} ← {mp}  "
            f"label='{snap.get('label')}'"
        )

    def _check_transfer(self, snap: dict, prev: dict):
        curr = snap.get("used_bytes")
        old  = prev.get("used_bytes")
        if curr is None or old is None:
            return
        delta = curr - old
        if delta >= self._xfer_limit:
            mb  = delta / (1024 * 1024)
            sev = Severity.HIGH if mb > 1024 else Severity.MEDIUM
            self._emit(
                "usb_data_transfer", snap,
                severity = sev,
                tags     = ["usb", "large_transfer", "data_exfiltration_risk"],
                notes    = (
                    f"Large USB write: {mb:.1f} MB on {snap['mountpoint']}  "
                    f"device={snap.get('device')}  label='{snap.get('label')}'"
                ),
            )
            print(
                f"Large USB write on {snap['mountpoint']}: {mb:.1f} MB"
            )

    # ── Linux raw-USB watcher ────────────────

    def _poll_raw_linux(self):
        """
        Secondary thread for Linux: detects USB mass-storage devices
        that appear in /sys/bus/usb but haven't been mounted yet.
        """
        print("USBCollector raw-device watcher started (Linux)")
        while not self._stop.is_set():
            try:
                current_raw = {
                    e["syspath"]: e for e in _linux_usb_raw_devices()
                }
                for syspath, entry in current_raw.items():
                    if syspath not in self._known_raw:
                        snap = {
                            "device":     syspath,
                            "mountpoint": "(not mounted)",
                            "fstype":     "unknown",
                            "opts":       "",
                            "label":      entry.get("prod_name", ""),
                            "vendor":     entry.get("mfr", ""),
                            "model":      entry.get("prod_name", ""),
                            "serial":     entry.get("serial", ""),
                            "size_bytes": 0,
                            "used_bytes": None,
                        }
                        self._emit(
                            "usb_raw_device", snap,
                            severity = Severity.MEDIUM,
                            tags     = ["usb_raw", "not_mounted"],
                            notes    = (
                                f"USB mass-storage device found (not yet mounted): "
                                f"vendor={entry.get('mfr')}  "
                                f"product={entry.get('prod_name')}  "
                                f"serial={entry.get('serial')}  "
                                f"vid={entry.get('vendor')}:{entry.get('product')}"
                            ),
                        )
                        print(
                            f"Raw USB device: {entry.get('mfr')} "
                            f"{entry.get('prod_name')} serial={entry.get('serial')}"
                        )
                self._known_raw = current_raw
            except Exception as e:
                print(f"Raw USB poll error: {e}")
            time.sleep(self._interval)

    # ── main poll loop ───────────────────────

    def _poll(self):
        print("USBCollector started — polling all partition types")

        # Seed silently so existing devices don't fire alerts at startup
        try:
            for part in psutil.disk_partitions(all=True):
                if _is_removable_partition(part):
                    snap = _build_snapshot(part)
                    self._known[part.mountpoint] = snap
            print(
                f"USBCollector seeded {len(self._known)} existing removable device(s): "
                + ", ".join(self._known.keys())
            )
        except Exception as e:
            print(f"USB seed error: {e}")

        while not self._stop.is_set():
            try:
                current: Dict[str, dict] = {}

                for part in psutil.disk_partitions(all=True):
                    if _is_removable_partition(part):
                        snap = _build_snapshot(part)
                        current[part.mountpoint] = snap

                # ── newly connected ──────────────
                for mp, snap in current.items():
                    if mp not in self._known:
                        self._check_connect(snap)

                # ── disconnected / removed ───────
                for mp, snap in list(self._known.items()):
                    if mp not in current:
                        self._check_disconnect(snap)   # uses saved snap — safe

                # ── transfer check ───────────────
                for mp, snap in current.items():
                    if mp in self._known:
                        self._check_transfer(snap, self._known[mp])

                self._known = current

            except Exception as e:
                print(f"USB poll error: {e}")

            time.sleep(self._interval)

    # ── lifecycle ────────────────────────────

    def start(self):
        t_main = threading.Thread(
            target=self._poll, daemon=True, name="usb-monitor"
        )
        self._threads = [t_main]
        t_main.start()

        if OS == "Linux":
            t_raw = threading.Thread(
                target=self._poll_raw_linux, daemon=True, name="usb-raw"
            )
            self._threads.append(t_raw)
            t_raw.start()

    def stop(self):
        self._stop.set()
