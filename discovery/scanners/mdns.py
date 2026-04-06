import json
import logging
import socket
import struct
import sys
import threading
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
    def __init__(self) -> None:
        self._listener_stop_events: dict[str, threading.Event] = {}
        self._listener_threads: dict[str, threading.Thread] = {}

    def stop(self) -> None:
        for event in self._listener_stop_events.values():
            event.set()

    def start_interface_listener(self, interface: str) -> None:
        """
        Spawn a background thread that joins the mDNS multicast group on the
        named interface and logs every received packet at DEBUG level.
        Calling this a second time for the same interface is a no-op.
        """
        if interface in self._listener_threads:
            logger.warning("mDNS listener already running on %s", interface)
            return
        stop_event = threading.Event()
        t = threading.Thread(
            target=self._listen_on_interface,
            args=(interface, stop_event),
            name=f"mdns-listener-{interface}",
            daemon=True,
        )
        self._listener_stop_events[interface] = stop_event
        self._listener_threads[interface] = t
        t.start()

    def _listen_on_interface(self, interface: str, stop_event: threading.Event) -> None:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            # Bind the socket to this specific interface before joining multicast
            # so we only receive traffic that arrived on it.
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode()
            )
            sock.bind(("", MDNS_PORT))
            # Join the IPv6 mDNS multicast group. The interface index in the
            # ipv6_mreq struct scopes the link-local membership to this interface.
            mreq = struct.pack(
                "16sI",
                socket.inet_pton(socket.AF_INET6, MDNS_ADDR6),
                socket.if_nametoindex(interface),
            )
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            sock.settimeout(1.0)
            logger.debug("mDNS listener started on %s", interface)

            while not stop_event.is_set():
                try:
                    data, (src_ip, _src_port, _flowinfo, _scope_id) = sock.recvfrom(4096)
                except TimeoutError:
                    continue

                pkt = DNS(data)
                logger.debug(
                    "[%s] mDNS from %s  questions=%d answers=%d additional=%d",
                    interface, src_ip, pkt.qdcount, pkt.ancount, pkt.arcount,
                )
                for i in range(pkt.qdcount):
                    qr = pkt.qd[i]
                    logger.debug(
                        "[%s]   QD: %r  type=%s",
                        interface, qr.qname, dnstypes.get(qr.qtype, qr.qtype),
                    )
                for i in range(pkt.ancount):
                    rr = pkt.an[i]
                    logger.debug(
                        "[%s]   AN: %r  type=%s  ttl=%d  rdata=%r",
                        interface, rr.rrname, dnstypes.get(rr.type, rr.type),
                        rr.ttl, rr.rdata,
                    )
                for i in range(pkt.arcount):
                    rr = pkt.ar[i]
                    logger.debug(
                        "[%s]   AR: %r  type=%s  ttl=%d  rdata=%r",
                        interface, rr.rrname, dnstypes.get(rr.type, rr.type),
                        rr.ttl, rr.rdata,
                    )
        except Exception as e:
            logger.error("mDNS listener error on %s", interface, exc_info=e)
        finally:
            sock.close()
            logger.debug("mDNS listener stopped on %s", interface)

    def start(self, args: list[str]):
        self.connect_to_server()
        if self.server is None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )
        # Announce to the server we are a scanner and give the list of parameters that we take
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


if __name__ == "__main__":
    scanner = MdnsScanner()
    # This fills out some basic information required to connect to the discovery server
    # It is done this way to enable the in-place re-exec style of privlege elevation
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
