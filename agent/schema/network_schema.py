from dataclasses import dataclass
from enum import Enum
from typing import Optional



class NetworkEventAction(str , Enum):
    CONNECT     = "connect"
    ACCEPT      = "accept"
    CLOSE       = "close"
    DNS_QUERY   = "dns_query"



@dataclass
class NetworkInfo:
    direction:          Optional[str]  = None   # inbound | outbound
    transport:          Optional[str]  = None   # tcp | udp | icmp
    protocol:           Optional[str]  = None   # http | dns | ssh | ftp ...
    src_ip:             Optional[str]  = None
    src_port:           Optional[int]  = None
    dst_ip:             Optional[str]  = None
    dst_port:           Optional[int]  = None
    bytes_sent:         Optional[int]  = None
    bytes_recv:         Optional[int]  = None
    packets_sent:       Optional[int]  = None
    packets_recv:       Optional[int]  = None
    connection_status:  Optional[str]  = None   # ESTABLISHED | LISTEN | TIME_WAIT ...
    dns_query:          Optional[str]  = None
    dns_response:       Optional[List[str]] = None
    geo_country:        Optional[str]  = None
    geo_city:           Optional[str]  = None
    is_private_ip:      Optional[bool] = None
