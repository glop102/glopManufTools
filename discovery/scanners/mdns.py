import argparse
import logging
import socket
import struct
import sys
import time
from select import select
from discovery.scanners.base_scanner import BaseScanner
from abc import abstractmethod
from typing import Optional, Protocol

from pydantic import BaseModel, ConfigDict
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
    Base class for mDNS wire records. Used only as an internal cache.
    Subclasses hold the parsed record data for each supported DNS record type.
    """
    model_config = ConfigDict(eq=False)

    interface: str     # Network interface this record was received on, e.g. 'eth0'
    rrname: str        # Fully-qualified domain name this record belongs to, e.g. 'mydevice.local.'
    ttl: int           # Seconds this record may be cached as reported by the sender
    received_at: float # time.time() timestamp when this record was last seen on the wire

    @abstractmethod
    def __hash__(self) -> int: ...


class MDNSARecord(MDNSResponseRecord):
    """A record — maps a hostname to an IPv4 address. Multiple per hostname are valid."""
    address: str  # IPv4 address string, e.g. '192.168.1.1'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MDNSARecord):
            return NotImplemented
        return (self.interface, self.rrname, self.address) == (other.interface, other.rrname, other.address)

    def __hash__(self) -> int:
        return hash((self.interface, self.rrname, self.address))


class MDNSAAAARecord(MDNSResponseRecord):
    """AAAA record — maps a hostname to an IPv6 address. Multiple per hostname are valid."""
    address: str  # IPv6 address string, e.g. 'fe80::1'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MDNSAAAARecord):
            return NotImplemented
        return (self.interface, self.rrname, self.address) == (other.interface, other.rrname, other.address)

    def __hash__(self) -> int:
        return hash((self.interface, self.rrname, self.address))


class MDNSPTRRecord(MDNSResponseRecord):
    """PTR record — maps a service type to a service instance name.
    Shared: multiple devices can each contribute a PTR for the same service type."""
    target: str  # Service instance name, e.g. 'My Printer._ipp._tcp.local.'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MDNSPTRRecord):
            return NotImplemented
        return (self.interface, self.rrname, self.target) == (other.interface, other.rrname, other.target)

    def __hash__(self) -> int:
        return hash((self.interface, self.rrname, self.target))


class MDNSTXTRecord(MDNSResponseRecord):
    """TXT record — key/value metadata for a service instance.
    Unique: one owner per name, so a new response replaces the old one."""
    entries: list[str]  # TXT strings, e.g. ['key=value', 'other=thing']

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MDNSTXTRecord):
            return NotImplemented
        return (self.interface, self.rrname) == (other.interface, other.rrname)

    def __hash__(self) -> int:
        return hash((self.interface, self.rrname))


class MDNSSRVRecord(MDNSResponseRecord):
    """SRV record — maps a service instance name to a host, port, and priority.
    Unique: one owner per service instance name."""
    priority: int
    weight: int
    port: int
    target: str  # Hostname of the machine providing the service, e.g. 'mydevice.local.'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MDNSSRVRecord):
            return NotImplemented
        return (self.interface, self.rrname) == (other.interface, other.rrname)

    def __hash__(self) -> int:
        return hash((self.interface, self.rrname))


class MDNSServiceData(BaseModel):
    """
    A single service with attached metadata about that service.
    This should be contained under a Host as services only make sense combined with a host.
    """

    instance_name: str          # Full service instance label from the PTR/SRV record rrname, e.g. 'My Printer._ipp._tcp.local.'
    service_type: str           # Service type portion of the instance name, e.g. '_ipp._tcp.local.'
    port: Optional[int] = None  # Port the service listens on, from the SRV record
    txt: dict[str, str] = {}    # Key/value metadata from the TXT record, e.g. {'version': '1.0', 'color': 'T'}

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

    interface: str              # Network interface this host was discovered on, e.g. 'eth0'
    hostname: str               # The machine's DNS hostname from the SRV target field, e.g. 'mydevice.local.'
    addresses: list[str] = []   # IP addresses resolved for this hostname via A/AAAA records
    services: list[MDNSServiceData] = []  # Services advertised by this host

    def __eq__(self, other) -> bool:
        """
        This equality check is asking "Are you the same host?" for purposes of hashing.
        Individual services and addresses may differ between copies if updates have happened.
        """
        if not isinstance(other, MDNSHostData):
            return NotImplemented
        return self.interface == other.interface and self.hostname == other.hostname

    def __hash__(self) -> int:
        return hash((self.interface, self.hostname))


class DNSRecord(Protocol):
    """Structural type covering the fields shared by all scapy DNS RR classes."""
    rrname: bytes        # Fully-qualified domain name this record belongs to, e.g. b'mydevice.local.'
    type: int            # DNS record type (A=1, PTR=12, TXT=16, AAAA=28, SRV=33, ...)
    ttl: int             # Seconds this record may be cached; 0 is a goodbye/withdrawal
    rdata: object        # Record data — type varies by record type (str, bytes, list, or scapy object)



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
        self.server.send_msg(announce)
        self.wait_for_registration()

        self._mdns_listener = self._create_mdns_listener(self._params.bind_address, self._params.port)
        self._active_interfaces: set[str] = set()
        # Each MDNSResponseRecord is hashed/compared by (interface, rrname, rtype, rdata)
        # so a discard+add upsert updates ttl/received_at without accumulating duplicates.
        self._record_cache: set[MDNSResponseRecord] = set()
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
        assert(self.server is not None)
        try:
            msgs = self.server.read_msgs()
        except ConnectionError:
            logger.info("Server connection closed, shutting down")
            self._keep_running = False
            return

        for msg in msgs:
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
                        # TODO - send messages about discovered devices on the interface we are leaving as disappearing devices
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

    def _process_rr(self, interface: str, rr: DNSRecord, now: float) -> str | None:
        """
        Upsert or remove one DNS resource record in the internal cache.
        Returns the rrname if the cache changed meaningfully (record added, removed,
        or content updated), or None for a TTL-only refresh with no data change.
        """
        rrname = rr.rrname.decode("utf-8", errors="replace")
        common = dict(interface=interface, rrname=rrname, ttl=rr.ttl, received_at=now)

        if rr.type == TYPE_A:
            record: MDNSResponseRecord = MDNSARecord(**common, address=rr.rdata)
        elif rr.type == TYPE_AAAA:
            record = MDNSAAAARecord(**common, address=rr.rdata)
        elif rr.type == TYPE_PTR:
            record = MDNSPTRRecord(**common, target=rr.rdata.decode("utf-8", errors="replace"))
        elif rr.type == TYPE_TXT:
            entries = [e.decode("utf-8", errors="replace") for e in rr.rdata]
            record = MDNSTXTRecord(**common, entries=entries)
        elif rr.type == TYPE_SRV:
            srv = rr.rdata
            record = MDNSSRVRecord(**common, priority=srv.priority, weight=srv.weight, port=srv.port, target=srv.target.decode("utf-8", errors="replace"))
        else:
            logger.debug("[%s] skipping unsupported record type %s", interface, dnstypes.get(rr.type, rr.type))
            return None

        if rr.ttl == 0:
            # Goodbye packet — the sender is withdrawing this record.
            if record in self._record_cache:
                self._record_cache.discard(record)
                logger.debug("[%s] removed record %r %s", interface, rrname, dnstypes.get(rr.type, rr.type))
                return rrname
            return None

        existing = next((r for r in self._record_cache if r == record), None)
        if existing is None:
            self._record_cache.add(record)
            return rrname

        # Record already exists. For A/AAAA/PTR the data is part of the identity key,
        # so equal records are always identical — this is just a TTL refresh.
        # For TXT and SRV the identity key excludes content fields, so we must compare
        # them explicitly to distinguish a real update from a refresh.
        content_changed = False
        if isinstance(record, MDNSTXTRecord) and isinstance(existing, MDNSTXTRecord):
            content_changed = record.entries != existing.entries
        elif isinstance(record, MDNSSRVRecord) and isinstance(existing, MDNSSRVRecord):
            content_changed = (record.priority, record.weight, record.port, record.target) != \
                              (existing.priority, existing.weight, existing.port, existing.target)

        self._record_cache.discard(existing)
        self._record_cache.add(record)
        return rrname if content_changed else None

    def _expire_records(self, now: float) -> set[str]:
        """
        Remove all cached records whose TTL has elapsed and return the set of
        rrnames that were affected.
        """
        expired = {r for r in self._record_cache if r.received_at + r.ttl < now}
        self._record_cache -= expired
        return {r.rrname for r in expired}

    def _handle_mdns_packet(self) -> None:
        data, ancdata, _flags, (src_ip, _src_port, _flowinfo, _scope_id) = self._mdns_listener.recvmsg(4096, 1024)

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

        # Skip queries — only responses carry authoritative record data.
        if not pkt.qr:
            return

        logger.debug(
            "[%s] mDNS response from %s  an=%d ns=%d ar=%d",
            interface, src_ip, pkt.ancount, pkt.nscount, pkt.arcount,
        )

        # pkt.an / ancount — Answer section
        # pkt.ns / nscount — Authority (Nameserver) section
        # pkt.ar / arcount — Additional Records section
        now = time.time()
        all_rrs = [section[i]
                   for count, section in ((pkt.ancount, pkt.an), (pkt.nscount, pkt.ns), (pkt.arcount, pkt.ar))
                   for i in range(count)]

        changed_rrnames: set[str] = set()
        for rr in all_rrs:
            logger.debug(
                "[%s]   %r  type=%s  ttl=%d  rdata=%r",
                interface, rr.rrname, dnstypes.get(rr.type, rr.type), rr.ttl, rr.rdata,
            )
            if rrname := self._process_rr(interface, rr, now):
                changed_rrnames.add(rrname)
        changed_rrnames |= self._expire_records(now)


if __name__ == "__main__":
    scanner = MdnsScanner()
    # This fills out some basic information required to connect to the discovery server
    # It is done this way to enable the in-place re-exec style of privlege elevation
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
