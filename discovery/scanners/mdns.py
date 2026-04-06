import json
import logging
import socket
import sys
from select import select
from discovery.scanners.base_scanner import BaseScanner
from typing import Optional

from pydantic import BaseModel, computed_field
from scapy.layers.dns import DNS, DNSQR, dnstypes

MDNS_ADDR6 = "ff02::fb"
MDNS_PORT = 5353

logger = logging.getLogger("discovery.mdns")

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33


class MDNSResponseRecord(BaseModel):
    """
    Individual response records seen on the wire.
    This is only planned on being used internally to cache values.
    """

    interface: str
    src_ip: str
    rrname: str
    rtype: int
    rdata: str
    ttl: int
    received_at: float

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
    """
    A single service with attached metadata about that service.
    This should be contained under a Host as services only make sense combined with a host.
    """

    instance_name: str
    service_type: str
    port: Optional[int] = None
    txt: dict[str, str] = {}

    def __eq__(self, other) -> bool:
        if not isinstance(other, MDNSServiceData):
            return NotImplemented
        return self.instance_name == other.instance_name

    def __hash__(self) -> int:
        return hash(self.instance_name)


class MDNSHostData(BaseModel):
    """
    A Host that has reported services being available.
    """

    interface: str
    hostname: str
    addresses: list[str] = []
    services: list[MDNSServiceData] = []

    def __eq__(self, other) -> bool:
        if not isinstance(other, MDNSHostData):
            return NotImplemented
        return self.interface == other.interface and self.hostname == other.hostname

    def __hash__(self) -> int:
        return hash((self.interface, self.hostname))


class MdnsScanner(BaseScanner):
    def stop(self) -> None:
        self._keep_running = False

    def _create_mdns_listener(self) -> socket.socket:
        """
        Create and return the mDNS listening socket without joining any multicast
        groups. IPV6_RECVPKTINFO is enabled so that recvmsg() will return an
        ancillary in6_pktinfo giving the exact incoming interface index for every
        received datagram, regardless of source address scope.
        Groups are joined separately as active interfaces are configured.
        """
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        sock.bind(("", MDNS_PORT))
        return sock

    def start(self, args: list[str]):
        self.connect_to_server()
        if self.server is None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )
        interfaces = [name for _, name in socket.if_nameindex()]
        announce = {
            "command": "announce",
            "type": "scanner",
            "name": "mdns.v1",
            "parameters": {},
            "interfaces": interfaces,
        }
        self.server.send_msg(json.dumps(announce))
        self.wait_for_registration()

        self._mdns_listener = self._create_mdns_listener()
        self._keep_running = True
        try:
            while self._keep_running:
                ready, _, _ = select([self.server, self._mdns_listener], [], [], 1.0)

                if self.server in ready:
                    logger.debug("Data available on server connection")
                    msgs = self.server.read_msgs()
                    # TODO: handle server commands

                if self._mdns_listener in ready:
                    logger.debug("Data available on mDNS listener")
                    data, ancdata, flags, addr = self._mdns_listener.recvmsg(4096, 1024)
                    # TODO: parse mDNS packet and ancdata for incoming interface
        finally:
            self._mdns_listener.close()


if __name__ == "__main__":
    scanner = MdnsScanner()
    # This fills out some basic information required to connect to the discovery server
    # It is done this way to enable the in-place re-exec style of privlege elevation
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
