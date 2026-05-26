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

# Import the new flat schema definitions
from schema.usb_schema import USBEvent, EventCategory, EventOutcome, Severity

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

REMOVABLE_FS: Set[str] = {
    "fat", "fat16", "fat32", "vfat", "exfat",
    "ntfs", "ntfs-3g",
    "hfs", "hfs+", "hfsplus", "apfs",
    "udf", "iso9660",
    "f2fs", "ext2", "ext3", "ext4",
}

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

def _linux_removable_flag(device: str) -> bool:
    try:
        base = re.sub(r'\d+$', '', Path(device).name)
        flag = Path(f"/sys/block/{base}/removable").read_text().strip()
        return flag == "1"
    except Exception:
        return False


def _linux_usb_raw_devices() -> List[dict]:
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
                break
    return results


def _linux_device_info(device: str) -> dict:
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


def _windows_removable_drives() -> List[dict]:
    drives = []
    try:
        import win32api, win32con
        drive_bits = win32api.GetLogicalDrives()
        for i in range(26):
            if drive_bits & (1 << i):
                letter = chr(65 + i) + ":\\"
                try:
                    dtype = win32api.GetDriveType(letter)
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


def _macos_disk_info(mountpoint: str) -> dict:
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
#  PARTITION FILTER
# ──────────────────────────────────────────────────────────────

def _is_removable_partition(part) -> bool:
    fs   = part.fstype.lower()
    opts = part.opts.lower()
    mp   = part.mountpoint

    if fs in SKIP_FS or not mp:
        return False

    if OS == "Linux":
        mp_l = mp.lower()
        if mp_l.startswith("/media/") or mp_l.startswith("/run/media/"):
            return True
        if mp_l.startswith("/mnt/"):
            dev = part.device
            if _linux_removable_flag(dev):
                return True
        if fs in REMOVABLE_FS and _linux_removable_flag(part.device):
            return True
        return False

    if OS == "Windows":
        if "removable" in opts:
            return True
        if len(mp) >= 2 and mp[1] == ":" and mp[0].upper() not in ("C",):
            if fs.lower() in REMOVABLE_FS:
                return True
        return False

    if OS == "Darwin":
        mp_l = mp.lower()
        if mp_l.startswith("/volumes/") and "macintosh hd" not in mp_l:
            info = _macos_disk_info(mp)
            if info["removable"] or "usb" in info["protocol"].lower():
                return True
            if fs in REMOVABLE_FS:
                return True
        return False

    return False


# ──────────────────────────────────────────────────────────────
#  SNAPSHOT BUILDER
# ──────────────────────────────────────────────────────────────

def _build_snapshot(part) -> dict:
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

    try:
        if OS == "Linux":
            info = _linux_device_info(dev)
            snap["label"]  = info.get("label", "")
            snap["serial"] = info.get("serial", "")
            snap["model"]  = info.get("model", "")
            snap["vendor"] = info.get("vendor", "")

        elif OS == "Darwin":
            info = _macos_disk_info(mp)
            snap["label"]  = info.get("label", "")
            snap["vendor"] = info.get("protocol", "")

        elif OS == "Windows":
            try:
                import win32api
                vol = win32api.GetVolumeInformation(mp)
                snap["label"]  = vol[0]
                snap["serial"] = hex(vol[1]) if vol[1] else ""
                snap["fstype"] = vol[4] if len(vol) > 4 else part.fstype
            except Exception:
                pass
    except Exception as e:
        print(f"Snapshot enrichment error on {mp}: {e}")

    try:
        usage = psutil.disk_usage(mp)
        snap["used_bytes"] = usage.used
        snap["size_bytes"] = usage.total
    except Exception:
        pass

    return snap


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
    Polls device topology and filesystems for dynamic external USB media mutations.
    Emits structural records adhering directly to USBEvent validation layers.
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

        self._known: Dict[str, dict] = {}
        self._known_raw: Dict[str, dict] = {}
        self._machine_info = machine_info

    def _emit(
        self,
        action: str,
        snap: dict,
        severity: Severity = Severity.INFO,
        outcome: EventOutcome = EventOutcome.SUCCESS,
        tags: List[str] = None,
        notes: str = None,
        extra_file_fields: dict = None,
        delta_bytes: int = None
    ):
        mp    = snap.get("mountpoint", snap.get("device", "unknown"))
        label = snap.get("label") or Path(mp).name or mp

        # Map dynamic snapshot values directly to the top-level flat schema attributes
        event = USBEvent(
            action=action,
            outcome=outcome,
            severity=severity,
            tags=(tags or []) + ["usb", "removable_media"],
            notes=notes,
            usb_device_path=snap.get("device"),
            usb_mountpoint=snap.get("mountpoint"),
            usb_fstype=snap.get("fstype"),
            usb_mount_options=snap.get("opts"),
            usb_label=snap.get("label"),
            usb_vendor=snap.get("vendor"),
            usb_model=snap.get("model"),
            usb_serial_number=snap.get("serial"),
            usb_size_bytes=snap.get("size_bytes"),
            usb_used_bytes=snap.get("used_bytes"),
            usb_transfer_delta_bytes=delta_bytes
        )

        # Enforce dynamic payload attributes if processing a custom subset category (e.g., File Contexts)

        if not event.notes:
            auto_notes = f"device={event.usb_device_path} fs={event.usb_fstype} label='{event.usb_label}'"
            if event.usb_serial_number: auto_notes += f" serial={event.usb_serial_number}"
            if event.usb_model:          auto_notes += f" model={event.usb_model}"
            if event.usb_size_bytes:     auto_notes += f" size={event.usb_size_bytes / (1024**3):.1f}GB"
            event.notes = auto_notes

        self._dispatch(event.to_dict(), self._machine_info)

    def _check_connect(self, snap: dict):
        mp    = snap["mountpoint"]
        label = (snap.get("label") or "").lower()
        tags  = ["usb_connected"]

        if any(bad in label for bad in SUSPICIOUS_LABELS):
            tags.append("suspicious_label")
            self._emit(
                "usb_connected", snap,
                severity=Severity.HIGH,
                tags=tags,
                notes=f"Suspicious USB label detected: '{snap.get('label')}' on {mp}",
            )
            print(f"Suspicious USB label '{snap.get('label')}' on {mp}")
        else:
            self._emit("usb_connected", snap, severity=Severity.LOW, tags=tags)
            print(f"USB connected: {snap.get('device')} → {mp} label='{snap.get('label')}'")

        if self._scan:
            bad = _scan_autorun_files(mp)
            for file_name in bad:
                is_autorun = file_name.lower() in AUTORUN_FILES
                sev = Severity.CRITICAL if is_autorun else Severity.HIGH
                
                file_fields = {
                    "file_path": str(Path(mp) / file_name),
                    "file_name": file_name,
                    "file_directory": mp
                }
                
                self._emit(
                    "usb_autorun_found", snap,
                    severity=sev,
                    outcome=EventOutcome.UNKNOWN,
                    tags=["usb", "autorun", "potential_malware"],
                    notes=f"Suspicious file discovered at USB root on {mp}: {file_name}",
                    extra_file_fields=file_fields
                )
                print(f"USB root risk file on {mp}: {file_name}")

    def _check_disconnect(self, snap: dict):
        mp = snap.get("mountpoint", "unknown")
        self._emit(
            "usb_disconnected", snap,
            severity=Severity.LOW,
            tags=["usb_disconnected"],
            notes=f"USB removed: device={snap.get('device','')} was mounted at {mp} label='{snap.get('label','')}'",
        )
        print(f"USB disconnected: {snap.get('device')} ← {mp}")

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
                severity=sev,
                tags=["usb", "large_transfer", "data_exfiltration_risk"],
                notes=f"Large USB write operation: {mb:.1f} MB on {snap['mountpoint']}",
                delta_bytes=delta
            )
            print(f"Large USB write on {snap['mountpoint']}: {mb:.1f} MB")

    def _poll_raw_linux(self):
        print("USBCollector raw-device watcher started (Linux)")
        while not self._stop.is_set():
            try:
                current_raw = {e["syspath"]: e for e in _linux_usb_raw_devices()}
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
                            severity=Severity.MEDIUM,
                            tags=["usb_raw", "not_mounted"],
                            notes=f"USB storage raw hardware detected (unmounted): vendor={entry.get('mfr')} product={entry.get('prod_name')}",
                        )
                        print(f"Raw USB hardware found: {entry.get('mfr')} {entry.get('prod_name')}")
                self._known_raw = current_raw
            except Exception as e:
                print(f"Raw USB hardware poll error: {e}")
            time.sleep(self._interval)

    def _poll(self):
        print("USBCollector started — polling storage configurations")
        try:
            for part in psutil.disk_partitions(all=True):
                if _is_removable_partition(part):
                    snap = _build_snapshot(part)
                    self._known[part.mountpoint] = snap
            print(f"USBCollector seeded {len(self._known)} existing device(s): " + ", ".join(self._known.keys()))
        except Exception as e:
            print(f"USB baseline seed error: {e}")

        while not self._stop.is_set():
            try:
                current: Dict[str, dict] = {}
                for part in psutil.disk_partitions(all=True):
                    if _is_removable_partition(part):
                        snap = _build_snapshot(part)
                        current[part.mountpoint] = snap

                # Connected mutations
                for mp, snap in current.items():
                    if mp not in self._known:
                        self._check_connect(snap)

                # Disconnected mutations
                for mp, snap in list(self._known.items()):
                    if mp not in current:
                        self._check_disconnect(snap)

                # IO Data Delta shifts
                for mp, snap in current.items():
                    if mp in self._known:
                        self._check_transfer(snap, self._known[mp])

                self._known = current
            except Exception as e:
                print(f"USB monitoring cluster poll error: {e}")

            time.sleep(self._interval)

    def start(self):
        t_main = threading.Thread(target=self._poll, daemon=True, name="usb-monitor")
        self._threads = [t_main]
        t_main.start()

        if OS == "Linux":
            t_raw = threading.Thread(target=self._poll_raw_linux, daemon=True, name="usb-raw")
            self._threads.append(t_raw)
            t_raw.start()

    def stop(self):
        self._stop.set()