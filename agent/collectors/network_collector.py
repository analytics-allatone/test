import re
import time
import socket
import ipaddress
import threading
from typing import Callable, Dict, Tuple, Optional

import psutil

# Importing the brand new flattened schema
from schema.network_schema import NetworkEvent, EventCategory, EventOutcome, Severity

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "smtp-tls",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb", 9200: "elasticsearch",
}

SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 6667, 12345}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def protocol_for_port(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, "unknown")


def severity_for_connection(dst_ip: str, dst_port: int) -> str:
    if dst_port in SUSPICIOUS_PORTS:
        return Severity.CRITICAL
    if not is_private_ip(dst_ip) and dst_port in {22, 3389, 445, 5900}:
        return Severity.HIGH
    if dst_port in {4444, 31337}:
        return Severity.CRITICAL
    if not is_private_ip(dst_ip) and dst_port in {23, 21}:
        return Severity.MEDIUM
    return Severity.INFO


class NetworkCollector:
    """
    Polls psutil.net_connections() to detect connection lifecycle events.
    Tracks per-NIC byte/packet counters for bandwidth anomaly detection.
    Maps everything to a strictly flattened NetworkEvent.
    """

    def __init__(
        self,
        dispatch:        Callable,
        machine_info: dict,
        poll_interval:   float = 2.0,
        track_bandwidth: bool  = True,
    ):
        self._dispatch        = dispatch
        self._interval        = poll_interval
        self._track_bw        = track_bandwidth
        self._stop            = threading.Event()
        self._thread          = None
        self._seen_conns: Dict[Tuple, dict] = {}   # key → connection snapshot
        self._prev_net_io     = None
        self._machine_info = machine_info

    @staticmethod
    def _conn_key(c) -> Tuple:
        laddr = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
        raddr = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
        return (c.family, c.type, laddr, raddr, c.pid)

    def _snapshot_conn(self, c) -> dict:
        laddr = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
        raddr = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
        return {
            "family":  c.family,
            "type":    c.type,
            "laddr":   laddr,
            "raddr":   raddr,
            "status":  c.status,
            "pid":     c.pid,
        }

    def _emit_connection(self, snap: dict, action: str):
        laddr  = snap["laddr"]
        raddr  = snap["raddr"]
        dst_ip = raddr[0]
        dst_port = raddr[1]

        transport = "tcp" if snap["type"] == socket.SOCK_STREAM else "udp"
        protocol  = protocol_for_port(dst_port)
        direction = "outbound" if laddr[1] > 1024 else "inbound"
        severity  = severity_for_connection(dst_ip, dst_port)

        if dst_port == 0 and laddr[1] < 1024:
            direction = "inbound"

        tags = ["network"]
        if dst_port in SUSPICIOUS_PORTS:
            tags.append("suspicious_port")
        if dst_ip and not is_private_ip(dst_ip):
            tags.append("external")

        mitre_tech = None
        mitre_tact = None
        if dst_port in {4444, 31337, 1337}:
            mitre_tech = "T1571"  # Non-Standard Port
            mitre_tact = "Command and Control"

        # Instantiate flat schema instance directly
        event = NetworkEvent(
            action                    = action,
            outcome                   = EventOutcome.SUCCESS,
            severity                  = severity,
            tags                      = tags,
            mitre_tactic              = mitre_tact,
            mitre_technique           = mitre_tech,
            # Flattened Network properties
            network_direction         = direction,
            network_transport         = transport,
            network_protocol          = protocol,
            network_src_ip            = laddr[0],
            network_src_port          = laddr[1],
            network_dst_ip            = dst_ip,
            network_dst_port          = dst_port,
            network_connection_status = snap.get("status"),
            network_is_private_ip     = is_private_ip(dst_ip) if dst_ip else None,
        )

        # Enrich with Flattened Process Context natively if PID exists
        pid = snap.get("pid")
        if pid:
            event.process_pid = pid
            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    event.process_ppid         = p.ppid()
                    event.process_name         = p.name()
                    event.process_executable   = p.exe()
                    event.process_command_line = " ".join(p.cmdline())
                    event.process_user         = p.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._dispatch(event.to_dict(), self._machine_info)

    def _poll(self):
        while not self._stop.is_set():
            try:
                current = {}
                conns = psutil.net_connections(kind="all")

                for c in conns:
                    key = self._conn_key(c)
                    current[key] = self._snapshot_conn(c)

                # New connections
                for key, snap in current.items():
                    if key not in self._seen_conns:
                        raddr = snap.get("raddr")
                        if raddr and raddr[0]:  # remote address must exist
                            self._emit_connection(snap, "connect")

                # Closed connections
                for key, snap in list(self._seen_conns.items()):
                    if key not in current:
                        raddr = snap.get("raddr")
                        if raddr and raddr[0]:
                            self._emit_connection(snap, "close")

                self._seen_conns = current

                if self._track_bw:
                    self._emit_bandwidth_stats()

            except Exception as ex:
                print(f"Network poll error: {ex}")

            time.sleep(self._interval)

    def _emit_bandwidth_stats(self):
        """Emit per-NIC I/O counters completely flattened out."""
        try:
            io = psutil.net_io_counters(pernic=True)
            if self._prev_net_io:
                for nic, counters in io.items():
                    prev = self._prev_net_io.get(nic)
                    if not prev:
                        continue
                    delta_sent = counters.bytes_sent - prev.bytes_sent
                    delta_recv = counters.bytes_recv - prev.bytes_recv
                    
                    if delta_sent > 1_000_000 or delta_recv > 1_000_000:  # > 1MB spike
                        event = NetworkEvent(
                            action             = "bandwidth_spike",
                            outcome            = EventOutcome.UNKNOWN,
                            severity           = Severity.MEDIUM,
                            network_bytes_sent = delta_sent,
                            network_bytes_recv = delta_recv,
                            tags               = ["bandwidth", nic],
                            notes              = f"NIC={nic} sent={delta_sent} recv={delta_recv}",
                        )
                        self._dispatch(event.to_dict(), self._machine_info)
            self._prev_net_io = io
        except Exception:
            pass

    def start(self):
        self._thread = threading.Thread(target=self._poll, daemon=True, name="net-monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()


class LinuxDNSCollector:
    """
    Tails system paths tracking DNS logs mapping straight to a flat footprint layout.
    """
    def __init__(self, dispatch: Callable, machine_info: dict):
        self._dispatch = dispatch
        self._machine_info = machine_info

    def emit_dns_query(self, query: str, src_ip: str, response: list = None):
        event = NetworkEvent(
            action               = "dns_query",
            outcome              = EventOutcome.SUCCESS,
            severity             = Severity.INFO,
            network_protocol     = "dns",
            network_src_ip       = src_ip,
            network_dst_port     = 53,
            network_dns_query    = query,
            network_dns_response = response,
            tags                 = ["dns", "network"],
        )
        self._dispatch(event.to_dict(), self._machine_info)