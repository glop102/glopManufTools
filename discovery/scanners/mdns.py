import argparse
import json
import logging
import socket
import struct
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

    def _create_mdns_listener(self, bind_address: str, port: int) -> socket.socket:
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
        sock.bind((bind_address, port))
        return sock

    def start(self, args: list[str]):
        parser = argparse.ArgumentParser(description="mDNS scanner")
        parser.add_argument(
            "--port",
            type=int,
            default=MDNS_PORT,
            help=f"UDP port to listen on (default: {MDNS_PORT})",
        )
        parser.add_argument(
            "--bind-address",
            default="::",
            help="IPv6 address to bind to (default: :: — all interfaces)",
        )
        self._params = parser.parse_args(args)

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
            "parameters": {
                "port": self._params.port,
                "bind_address": self._params.bind_address,
            },
            "interfaces": interfaces,
        }
        self.server.send_msg(json.dumps(announce))
        self.wait_for_registration()

        self._mdns_listener = self._create_mdns_listener(self._params.bind_address, self._params.port)
        self._active_interfaces: set[str] = set()
        self._keep_running = True
        try:
            while self._keep_running:
                ready, _, _ = select([self.server, self._mdns_listener], [], [], 1.0)

                if self.server in ready:
                    self._handle_server_msgs()

                if self._mdns_listener in ready:
                    self._handle_mdns_packet()
        finally:
            self._mdns_listener.close()

    def _join_interface(self, interface: str) -> None:
        mreq = struct.pack(
            "16sI",
            socket.inet_pton(socket.AF_INET6, MDNS_ADDR6),
            socket.if_nametoindex(interface),
        )
        self._mdns_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self._active_interfaces.add(interface)
        logger.debug("Joined mDNS multicast group on %s", interface)

    def _leave_interface(self, interface: str) -> None:
        mreq = struct.pack(
            "16sI",
            socket.inet_pton(socket.AF_INET6, MDNS_ADDR6),
            socket.if_nametoindex(interface),
        )
        self._mdns_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)
        self._active_interfaces.discard(interface)
        logger.debug("Left mDNS multicast group on %s", interface)

    def _handle_server_msgs(self) -> None:
        try:
            msgs = self.server.read_msgs()
        except ConnectionError:
            logger.info("Server connection closed, shutting down")
            self._keep_running = False
            return

        for raw in msgs:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Non-JSON message from server: %r", raw)
                continue

            match msg.get("command"):
                case "set_scanner_parameters":
                    changed = []
                    for entry in msg.get("parameters", []):
                        name = entry.get("name")
                        value = entry.get("value")
                        if not hasattr(self._params, name):
                            logger.warning("Ignoring unknown parameter %r", name)
                            continue
                        if getattr(self._params, name) == value:
                            continue
                        setattr(self._params, name, value)
                        changed.append(name)
                        logger.debug("Parameter %r changed to %r", name, value)
                    if changed:
                        if "port" in changed or "bind_address" in changed:
                            self._mdns_listener.close()
                            # TODO - add the cache_clear handler method here since a new socket invalidates all discoveries
                            self._mdns_listener = self._create_mdns_listener(
                                self._params.bind_address, self._params.port
                            )
                            for iface in self._active_interfaces:
                                self._join_interface(iface)
                        self.server.send_msg({
                            "command": "parameters_changed",
                            "parameters": [
                                {"name": n, "value": getattr(self._params, n)}
                                for n in changed
                            ],
                        })

                case "set_active_interfaces":
                    requested = set(msg.get("interfaces", []))
                    for iface in requested - self._active_interfaces:
                        try:
                            self._join_interface(iface)
                        except OSError:
                            logger.warning("Failed to join mDNS group on %s, interface may have disappeared", iface, exc_info=True)
                    for iface in self._active_interfaces - requested:
                        self._leave_interface(iface)
                        # TODO - send messages about discovered devices on the interfae we are leaving
                    self.server.send_msg({
                        "command": "active_interfaces_changed",
                        "interfaces": list(self._active_interfaces),
                    })

                case "clear_cache":
                    # TODO: clear internal result state, then repopulate via scan_results_update
                    logger.debug("clear_cache received")

                case "stop_scanner":
                    logger.info("stop_scanner received, shutting down")
                    self._keep_running = False

                case unknown:
                    logger.warning("Unknown command from server: %r", unknown)

    def _handle_mdns_packet(self) -> None:
        data, ancdata, flags, (src_ip, _src_port, _flowinfo, _scope_id) = self._mdns_listener.recvmsg(4096, 1024)

        interface = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO:
                _ipi6_addr, ipi6_ifindex = struct.unpack("16sI", cmsg_data)
                interface = socket.if_indextoname(ipi6_ifindex)
                break
        if interface is None:
            logger.warning("Received mDNS packet with no IPV6_PKTINFO ancdata, dropping")
            return

        pkt = DNS(data)
        logger.debug(
            "[%s] mDNS from %s  qd=%d an=%d ns=%d ar=%d",
            interface, src_ip, pkt.qdcount, pkt.ancount, pkt.nscount, pkt.arcount,
        )
        for i in range(pkt.qdcount):
            qr = pkt.qd[i]
            logger.debug(
                "[%s]   QD: %r  type=%s  class=%d",
                interface, qr.qname, dnstypes.get(qr.qtype, qr.qtype), qr.qclass,
            )
        for i in range(pkt.ancount):
            rr = pkt.an[i]
            logger.debug(
                "[%s]   AN: %r  type=%s  ttl=%d  rdata=%r",
                interface, rr.rrname, dnstypes.get(rr.type, rr.type), rr.ttl, rr.rdata,
            )
        for i in range(pkt.nscount):
            rr = pkt.ns[i]
            logger.debug(
                "[%s]   NS: %r  type=%s  ttl=%d  rdata=%r",
                interface, rr.rrname, dnstypes.get(rr.type, rr.type), rr.ttl, rr.rdata,
            )
        for i in range(pkt.arcount):
            rr = pkt.ar[i]
            logger.debug(
                "[%s]   AR: %r  type=%s  ttl=%d  rdata=%r",
                interface, rr.rrname, dnstypes.get(rr.type, rr.type), rr.ttl, rr.rdata,
            )


if __name__ == "__main__":
    scanner = MdnsScanner()
    # This fills out some basic information required to connect to the discovery server
    # It is done this way to enable the in-place re-exec style of privlege elevation
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
