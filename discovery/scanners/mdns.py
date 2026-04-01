import json
import socket
import sys
from discovery.scanners.base_scanner import BaseScanner
from typing import Optional

from pydantic import BaseModel, computed_field
from scapy.layers.dns import DNS, DNSQR, dnstypes

MDNS_ADDR6 = "ff02::fb"
MDNS_PORT = 5353

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

class MDNSResponseRecord(BaseModel):
    interface: str
    src_ip: str
    rrname: str
    rtype: int
    rdata: str
    ttl: int
    received_at: float
    response_time: Optional[float] = None  # None if record arrived unsolicited

    @computed_field
    @property
    def type_name(self) -> str:
        return dnstypes.get(self.rtype, str(self.rtype))

    @computed_field
    @property
    def is_shared(self) -> bool:
        """PTR records are shared (multiple devices can answer for one service type)."""
        return self.rtype == TYPE_PTR


class MDNSServiceData(BaseModel):
    interface: str
    instance_name: str
    service_type: str
    hostname: Optional[str] = None
    port: Optional[int] = None
    addresses: list[str] = []
    txt: dict[str, str] = {}

    def __eq__(self, other) -> bool:
        if not isinstance(other, MDNSServiceData):
            return NotImplemented
        return self.interface == other.interface and self.instance_name == other.instance_name

    def __hash__(self) -> int:
        return hash((self.interface, self.instance_name))

class MdnsScanner(BaseScanner):
    def start(self, args: list[str]):
        _ = self.parse_args(args)
        self.connect_to_server()
        if self.server == None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )
        # Announce to the server we are a scanner and give the list of parameters that we take
        interfaces = [name for _, name in socket.if_nameindex()]
        announce = {
            "command": "announce",
            "type": "scanner",
            "name": "mdns",
            "parameters": ["domains"],
            "interfaces": interfaces,
        }
        self.server.send_msg(json.dumps(announce))
        # TODO - check if the server connection closed and then exit


if __name__ == "__main__":
    scanner = MdnsScanner()
    scanner.start(sys.argv[1:])
