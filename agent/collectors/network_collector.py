import re
import time
import socket
import ipaddress
import threading
from typing import Callable, Dict, Tuple, Optional

import psutil

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from schema.event_schema import (
    SentinelEvent, NetworkInfo, ProcessInfo, UserInfo,
    EventCategory, EventAction, EventOutcome, Severity,
    get_host_info
)


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


def severity_for_connection(dst_ip: str, dst_port: int, status: str) -> str:
    if dst_port in SUSPICIOUS_PORTS:
        return Severity.CRITICAL
    if not is_private_ip(dst_ip) and dst_port in {22, 3389, 445, 5900}:
        return Severity.HIGH
    if dst_port in {4444, 31337}:
        return Severity.CRITICAL
    if not is_private_ip(dst_ip) and dst_port in {23, 21}:
        return Severity.MEDIUM
    return Severity.INFO


def _get_process_for_conn(pid: Optional[int]) -> Optional[ProcessInfo]:
    if not pid:
        return None
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return ProcessInfo(
                pid          = pid,
                ppid         = p.ppid(),
                name         = p.name(),
                executable   = p.exe(),
                command_line = " ".join(p.cmdline()),
                user         = p.username(),
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ProcessInfo(pid=pid)



class NetworkCollector:
    """
    Polls psutil.net_connections() to detect connection lifecycle events.
    Also tracks per-NIC byte/packet counters for bandwidth anomaly detection.
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
        severity  = severity_for_connection(dst_ip, dst_port, snap.get("status",""))

        # Determine if it's inbound based on ports
        if dst_port == 0 and laddr[1] < 1024:
            direction = "inbound"

        net_info = NetworkInfo(
            direction        = direction,
            transport        = transport,
            protocol         = protocol,
            src_ip           = laddr[0],
            src_port         = laddr[1],
            dst_ip           = dst_ip,
            dst_port         = dst_port,
            connection_status= snap.get("status"),
            is_private_ip    = is_private_ip(dst_ip) if dst_ip else None,
        )

        proc_info = _get_process_for_conn(snap.get("pid"))

        tags = ["network"]
        if dst_port in SUSPICIOUS_PORTS:
            tags.append("suspicious_port")
        if not is_private_ip(dst_ip) and dst_ip:
            tags.append("external")

        mitre_tech = None
        if dst_port in {4444, 31337, 1337}:
            mitre_tech = "T1571"  # Non-Standard Port

        event = SentinelEvent(
            category        = EventCategory.NETWORK,
            action          = action,
            outcome         = EventOutcome.SUCCESS,
            severity        = severity,
            collector       = "network_monitor",
            host            = get_host_info(),
            network         = net_info,
            process         = proc_info,
            tags            = tags,
            raw_log         = snap,
            mitre_tactic    = "Command and Control" if mitre_tech else None,
            mitre_technique = mitre_tech,
        )
        self._dispatch(event.to_dict() , self._machine_info)

    # def _poll(self):
    #     while not self._stop.is_set():
    #         try:
    #             current = {}
    #             conns = psutil.net_connections(kind="all")
    #             for c in conns:
    #                 key = self._conn_key(c)
    #                 current[key] = self._snapshot_conn(c)

    #             # New connections
    #             for key, snap in current.items():
    #                 if key not in self._seen_conns:
    #                     if snap["raddr"][0]:  # only emit if remote addr exists
    #                         self._emit_connection(snap, EventAction.CONNECT)

    #             # Closed connections
    #             for key, snap in self._seen_conns.items():
    #                 if key not in current:
    #                     if snap["raddr"][0]:
    #                         self._emit_connection(snap, EventAction.CLOSE)

    #             self._seen_conns = current

    #             # Bandwidth stats
    #             if self._track_bw:
    #                 self._emit_bandwidth_stats()

    #         except Exception as ex:
    #             print(f"Network poll error: {ex}")

    #         time.sleep(self._interval)


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
                    raddr = snap.get("raddr")
                    if raddr:
                        self._emit_connection(snap, EventAction.CONNECT)

                # Closed connections
                for key, snap in list(self._seen_conns.items()):
                    if key not in current:
                        raddr = snap.get("raddr")
                        if raddr:
                            self._emit_connection(snap, EventAction.CLOSE)

                self._seen_conns = current

                if self._track_bw:
                    self._emit_bandwidth_stats()

            except Exception as ex:
                print(f"Network poll error: {ex}")

            time.sleep(self._interval)

    def _emit_bandwidth_stats(self):
        """Emit per-NIC I/O counters as a system event."""
        try:
            io = psutil.net_io_counters(pernic=True)
            if self._prev_net_io:
                for nic, counters in io.items():
                    prev = self._prev_net_io.get(nic)
                    if not prev:
                        continue
                    delta_sent = counters.bytes_sent - prev.bytes_sent
                    delta_recv = counters.bytes_recv - prev.bytes_recv
                    if delta_sent > 1_000_000 or delta_recv > 1_000_000:  # > 1MB in interval
                        event = SentinelEvent(
                            category  = EventCategory.NETWORK,
                            action    = "bandwidth_spike",
                            outcome   = EventOutcome.UNKNOWN,
                            severity  = Severity.MEDIUM,
                            collector = "network_monitor",
                            host      = get_host_info(),
                            network   = NetworkInfo(
                                bytes_sent = delta_sent,
                                bytes_recv = delta_recv,
                            ),
                            tags      = ["bandwidth", nic],
                            notes     = f"NIC={nic} sent={delta_sent} recv={delta_recv}",
                        )
                        self._dispatch(event.to_dict() , self._machine_info)
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
    Tails /var/log/syslog or /var/log/messages for DNS queries (dnsmasq/systemd-resolved).
    Also monitors /etc/resolv.conf and /etc/hosts for changes (integrity).
    """

    DNS_PATTERNS = [
        # dnsmasq
        (re.compile(r"dnsmasq\[\d+\]: query\[(\S+)\] (\S+) from ([\d.]+)"), "dnsmasq"),
        # systemd-resolved (journal)
        (re.compile(r"systemd-resolved.*Received query.*QNAME: (\S+)"), "resolved"),
    ]

    def __init__(self, dispatch: Callable ,  machine_info: dict):
        self._dispatch = dispatch
        self._machine_info =  machine_info

    def emit_dns_query(self, query: str, src_ip: str, response: list = None):
        event = SentinelEvent(
            category  = EventCategory.NETWORK,
            action    = EventAction.DNS_QUERY,
            outcome   = EventOutcome.SUCCESS,
            severity  = Severity.INFO,
            collector = "dns_monitor",
            host      = get_host_info(),
            network   = NetworkInfo(
                protocol    = "dns",
                src_ip      = src_ip,
                dst_port    = 53,
                dns_query   = query,
                dns_response= response,
            ),
            tags = ["dns", "network"],
        )
        self._dispatch(event.to_dict() , self._machine_info)