import argparse
import logging
import socket
import struct
import sys
import time
from select import select
from discovery.scanners.base_scanner import BaseScanner
from abc import ABC, abstractmethod
from typing import Optional, Protocol, TypedDict

from pydantic import BaseModel, ConfigDict, ValidationError

from discovery.commands import (
    ScannerActiveInterfacesChanged,
    ScannerAnnounce,
    ScannerAvailableInterfacesChanged,
    ScannerParametersChanged,
    ScannerResultsRemove,
    ScannerResultsUpdate,
    ScanResultItem,
    ServerClearCache,
    ServerSetActiveInterfaces,
    ServerSetScannerParameters,
    ServerStopScanner,
    ServerToScannerMessageAdapter,
    StatusResponse,
    ParameterUpdate,
)
from scapy.layers.dns import DNS, DNSQR, dnstypes

MDNS_ADDR6 = "ff02::fb"
MDNS_PORT = 5353

logger = logging.getLogger("discovery.mdns")

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

class MDNSResponseRecord(BaseModel, ABC):
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
    # SRV-specific fields (DNSRRSRV exposes these as direct attributes, not via rdata)
    priority: int
    weight: int
    port: int
    target: bytes




class _CommonRRFields(TypedDict):
    # Used for dict explansion but typed to make the linetr happy. Just used for _process_rr
    interface: str
    rrname: str
    ttl: int
    received_at: float


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
        parser.add_argument(
            "--query-domain",
            default="_services._dns-sd._udp.local.",
            help="mDNS PTR query domain to send periodically (default: _services._dns-sd._udp.local.)",
        )
        parser.add_argument(
            "--active-query-delay",
            type=float,
            default=4.0,
            help="Seconds between active mDNS queries (default: 4.0)",
        )
        parser.add_argument(
            "--multicast-group",
            default=MDNS_ADDR6,
            help=f"IPv6 multicast group to join and query (default: {MDNS_ADDR6})",
        )
        self._params = parser.parse_args(args)

        self.connect_to_server()
        if self.server is None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )
        self._available_interfaces: set[str] = {name for _, name in socket.if_nameindex()}
        self.server.send_cmd(ScannerAnnounce(
            name="mdns.v1",
            parameters=vars(self._params),
            interfaces=list(self._available_interfaces),
        ))
        self.wait_for_registration()

        self._mdns_listener = self._create_mdns_listener(self._params.bind_address, self._params.port)
        self._active_interfaces: set[str] = set()
        # Each MDNSResponseRecord is hashed/compared by (interface, rrname, rtype, rdata)
        # so a discard+add upsert updates ttl/received_at without accumulating duplicates.
        self._record_cache: set[MDNSResponseRecord] = set()
        self._last_query_time: float = 0.0
        self._keep_running = True
        try:
            while self._keep_running:
                ready, _, _ = select([self.server, self._mdns_listener], [], [], 1.0)

                if self.server in ready:
                    self._handle_server_msgs()

                if self._mdns_listener in ready:
                    self._handle_mdns_packet()

                self._check_interfaces()

                now = time.time()
                if now - self._last_query_time >= self._params.active_query_delay:
                    self._send_query()
                    self._last_query_time = now
        finally:
            self._mdns_listener.close()

    def _join_interface(self, interface: str) -> None:
        mreq = struct.pack(
            "16sI",
            socket.inet_pton(socket.AF_INET6, self._params.multicast_group),
            socket.if_nametoindex(interface),
        )
        self._mdns_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self._active_interfaces.add(interface)
        logger.debug("Joined mDNS multicast group on %s", interface)

    def _leave_interface(self, interface: str) -> None:
        assert self.server is not None
        mreq = struct.pack(
            "16sI",
            socket.inet_pton(socket.AF_INET6, self._params.multicast_group),
            socket.if_nametoindex(interface),
        )
        self._mdns_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)
        self._active_interfaces.discard(interface)
        logger.debug("Left mDNS multicast group on %s", interface)

        known_keys = (
            {f"{r.interface}/{r.rrname}" for r in self._record_cache if isinstance(r, (MDNSARecord, MDNSAAAARecord)) and r.interface == interface}
            | {f"{r.interface}/{r.target}" for r in self._record_cache if isinstance(r, MDNSSRVRecord) and r.interface == interface}
        )
        self._record_cache = {r for r in self._record_cache if r.interface != interface}
        if known_keys:
            self.server.send_cmd( ScannerResultsRemove(keys=list(known_keys)))

    def _check_interfaces(self) -> None:
        """
        Detect interface changes and notify the broker. Called every main loop iteration.
        - Appeared interfaces: report updated available list to broker.
        - Disappeared interfaces: leave any we were active on (which cleans up records and
          notifies the broker of removed hosts), then report updated available and active lists.
        """
        assert self.server is not None
        current = {name for _, name in socket.if_nameindex()}
        appeared = current - self._available_interfaces
        disappeared = self._available_interfaces - current

        if not appeared and not disappeared:
            return

        active_changed = False
        for iface in disappeared:
            if iface in self._active_interfaces:
                self._leave_interface(iface)
                active_changed = True

        self._available_interfaces = current

        if active_changed:
            self.server.send_cmd( ScannerActiveInterfacesChanged(interfaces=list(self._active_interfaces)))
        self.server.send_cmd( ScannerAvailableInterfacesChanged(interfaces=list(self._available_interfaces)))

    def _send_query(self) -> None:
        """Send PTR queries: one for the top-level meta-domain plus one per known service type."""
        if not self._active_interfaces:
            return
        query_domain = self._params.query_domain.rstrip(".")
        # Only pick up PTR records in our question records if they were sent in response to our
        # original top level query domain. ie do not query for MyPrinter._ipp._tcp.local as that is nonsense
        known_service_types = {
            r.target for r in self._record_cache
            if isinstance(r, MDNSPTRRecord) and r.rrname.rstrip(".") == query_domain
        }
        questions = [DNSQR(qname=self._params.query_domain, qtype="PTR")]
        questions += [DNSQR(qname=stype, qtype="PTR") for stype in known_service_types]
        pkt = bytes(DNS(rd=0, qd=questions))
        for iface in self._active_interfaces:
            self._mdns_listener.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_MULTICAST_IF,
                struct.pack("I", socket.if_nametoindex(iface)),
            )
            self._mdns_listener.sendto(pkt, (self._params.multicast_group, self._params.port))
            logger.debug(
                "[%s] sent mDNS query for %s + %d service type(s)",
                iface, self._params.query_domain, len(known_service_types),
            )

    def _handle_server_msgs(self) -> None:
        assert(self.server is not None)
        try:
            msgs = self.server.read_msgs()
        except ConnectionError:
            logger.info("Server connection closed, shutting down")
            self._keep_running = False
            return

        for raw in msgs:
            try:
                cmd = ServerToScannerMessageAdapter.validate_python(raw)
            except ValidationError:
                logger.warning("Unknown/invalid command from server: %r", raw.get("command"))
                continue

            match cmd:
                case ServerSetScannerParameters():
                    changed = []
                    for entry in cmd.parameters:
                        if not hasattr(self._params, entry.name):
                            logger.warning("Ignoring unknown parameter %r", entry.name)
                            continue
                        if getattr(self._params, entry.name) == entry.value:
                            continue
                        setattr(self._params, entry.name, entry.value)
                        changed.append(entry.name)
                        logger.debug("Parameter %r changed to %r", entry.name, entry.value)
                    if changed:
                        if "port" in changed or "bind_address" in changed or "multicast_group" in changed:
                            self._mdns_listener.close()
                            self._clear_cache()
                            self._mdns_listener = self._create_mdns_listener(
                                self._params.bind_address, self._params.port
                            )
                            for iface in self._active_interfaces:
                                self._join_interface(iface)
                        self.server.send_cmd( ScannerParametersChanged(parameters=[
                            ParameterUpdate(name=n, value=getattr(self._params, n)) for n in changed
                        ]))

                case ServerSetActiveInterfaces():
                    requested = set(cmd.interfaces)
                    for iface in requested - self._active_interfaces:
                        try:
                            self._join_interface(iface)
                        except OSError:
                            logger.warning("Failed to join mDNS group on %s, interface may have disappeared", iface, exc_info=True)
                    for iface in self._active_interfaces - requested:
                        self._leave_interface(iface)
                    self.server.send_cmd( ScannerActiveInterfacesChanged(interfaces=list(self._active_interfaces)))

                case ServerClearCache():
                    logger.debug("clear_cache received")
                    self._clear_cache()

                case StatusResponse():
                    pass  # acknowledgement from server

                case ServerStopScanner():
                    logger.info("stop_scanner received, shutting down")
                    self._keep_running = False

    def _clear_cache(self) -> None:
        """
        Clear all internal record state and notify the broker to remove any previously
        reported hosts. Safe to call when the broker has already cleared its own cache —
        it filters unknown keys so the remove becomes a no-op.
        """
        assert self.server is not None
        known_keys = (
            {f"{r.interface}/{r.rrname}" for r in self._record_cache if isinstance(r, (MDNSARecord, MDNSAAAARecord))}
            | {f"{r.interface}/{r.target}" for r in self._record_cache if isinstance(r, MDNSSRVRecord)}
        )
        self._record_cache.clear()
        logger.info("Cache cleared, removing %d previously reported hosts", len(known_keys))
        if known_keys:
            self.server.send_cmd( ScannerResultsRemove(keys=list(known_keys)))

    def _process_rr(self, interface: str, rr: DNSRecord, now: float) -> MDNSResponseRecord | None:
        """
        Upsert or remove one DNS resource record in the internal cache.
        Returns the record if the cache changed meaningfully (record added, removed,
        or content updated), or None for a TTL-only refresh with no data change.
        """
        rrname = rr.rrname.decode("utf-8", errors="replace")
        common = _CommonRRFields(interface=interface, rrname=rrname, ttl=rr.ttl, received_at=now)

        if rr.type == TYPE_A:
            assert isinstance(rr.rdata, str)
            record: MDNSResponseRecord = MDNSARecord(**common, address=rr.rdata)
        elif rr.type == TYPE_AAAA:
            assert isinstance(rr.rdata, str)
            record = MDNSAAAARecord(**common, address=rr.rdata)
        elif rr.type == TYPE_PTR:
            assert isinstance(rr.rdata, bytes)
            record = MDNSPTRRecord(**common, target=rr.rdata.decode("utf-8", errors="replace"))
        elif rr.type == TYPE_TXT:
            assert isinstance(rr.rdata, list)
            entries = [e.decode("utf-8", errors="replace") for e in rr.rdata]
            record = MDNSTXTRecord(**common, entries=entries)
        elif rr.type == TYPE_SRV:
            record = MDNSSRVRecord(**common, priority=rr.priority, weight=rr.weight, port=rr.port, target=rr.target.decode("utf-8", errors="replace"))
        else:
            logger.debug("[%s] skipping unsupported record type %s", interface, dnstypes.get(rr.type, rr.type))
            return None

        if rr.ttl == 0:
            # Goodbye packet — the sender is withdrawing this record.
            if record in self._record_cache:
                self._record_cache.discard(record)
                logger.debug("[%s] removed record %r %s", interface, rrname, dnstypes.get(rr.type, rr.type))
                return record
            return None

        existing = next((r for r in self._record_cache if r == record), None)
        if existing is None:
            self._record_cache.add(record)
            return record

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
        return record if content_changed else None

    def _expire_records(self, now: float) -> set[MDNSResponseRecord]:
        """
        Remove all cached records whose TTL has elapsed and return the expired records.
        """
        expired = {r for r in self._record_cache if r.received_at + r.ttl < now}
        self._record_cache -= expired
        return expired

    def _resolve_affected_hostnames(self, changed: set[MDNSResponseRecord]) -> set[tuple[str, str]]:
        """
        Walk changed records to find all (interface, hostname) pairs that need updating.

        - A/AAAA:   directly affected hostname
        - SRV/TXT:  follow SRV target to get the hostname
        - PTR:      follow PTR targets (instance names) then SRV targets to get hostnames
        """
        affected: set[tuple[str, str]] = set()
        for r in changed:
            if isinstance(r, (MDNSARecord, MDNSAAAARecord)):
                affected.add((r.interface, r.rrname))
            elif isinstance(r, (MDNSSRVRecord, MDNSTXTRecord)):
                for srv in self._record_cache:
                    if isinstance(srv, MDNSSRVRecord) and srv.rrname == r.rrname and srv.interface == r.interface:
                        affected.add((srv.interface, srv.target))
            elif isinstance(r, MDNSPTRRecord):
                for ptr in self._record_cache:
                    if not (isinstance(ptr, MDNSPTRRecord) and ptr.rrname == r.rrname and ptr.interface == r.interface):
                        continue
                    for srv in self._record_cache:
                        if isinstance(srv, MDNSSRVRecord) and srv.rrname == ptr.target and srv.interface == r.interface:
                            affected.add((srv.interface, srv.target))
        return affected

    def _build_host_data(self, interface: str, hostname: str) -> MDNSHostData:
        """Build an MDNSHostData from the current record cache for the given host."""
        addresses = [
            r.address for r in self._record_cache
            if isinstance(r, (MDNSARecord, MDNSAAAARecord)) and r.rrname == hostname and r.interface == interface
        ]

        # Find all service instances whose SRV points to this hostname
        srv_by_instance = {
            r.rrname: r for r in self._record_cache
            if isinstance(r, MDNSSRVRecord) and r.target == hostname and r.interface == interface
        }

        services = []
        for instance_name, srv in srv_by_instance.items():
            # Resolve service type from the PTR record whose target is this instance
            service_type = next(
                (r.rrname for r in self._record_cache
                 if isinstance(r, MDNSPTRRecord) and r.target == instance_name and r.interface == interface),
                None,
            )
            if service_type is None:
                continue

            # Parse TXT entries into a key/value dict
            txt: dict[str, str] = {}
            txt_record = next(
                (r for r in self._record_cache
                 if isinstance(r, MDNSTXTRecord) and r.rrname == instance_name and r.interface == interface),
                None,
            )
            if txt_record:
                for entry in txt_record.entries:
                    key, _, value = entry.partition('=')
                    txt[key] = value

            services.append(MDNSServiceData(
                instance_name=instance_name,
                service_type=service_type,
                port=srv.port,
                txt=txt,
            ))

        return MDNSHostData(interface=interface, hostname=hostname, addresses=addresses, services=services)

    def _handle_mdns_packet(self) -> None:
        assert(self.server is not None)
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

        try:
            pkt = DNS(data)
        except Exception:
            logger.warning("[%s] Failed to parse mDNS packet from %s, dropping", interface, src_ip, exc_info=True)
            return

        # Skip queries — only responses carry authoritative record data.
        if not pkt.qr:
            return

        logger.debug(
            "[%s] mDNS response from %s  an=%d ns=%d ar=%d",
            interface, src_ip, pkt.ancount, pkt.nscount, pkt.arcount,
        )

        now = time.time()
        # an=answer records, ns=authoritative nameservers, ar=additional records
        all_rrs = [rr for section in (pkt.an, pkt.ns, pkt.ar) for rr in section]

        changed_records: set[MDNSResponseRecord] = set()
        for rr in all_rrs:
            if not hasattr(rr, "ttl"):
                # Some record types (e.g. OPT/type 41) are represented by scapy without
                # standard DNS RR fields; skip them.
                logger.debug("[%s]   skipping record with no ttl (type=%s)", interface, getattr(rr, "type", "?"))
                continue
            logger.debug(
                "[%s]   %r  type=%s  ttl=%d  rdata=%r",
                interface, rr.rrname, dnstypes.get(rr.type, rr.type), rr.ttl, getattr(rr, "rdata", None),
            )
            if changed := self._process_rr(interface, rr, now):
                changed_records.add(changed)
        # Putting the cache expiry here in the packet handler with the expectation to have
        # returned answers regularly to our periodic service query
        changed_records |= self._expire_records(now)

        if not changed_records:
            return

        affected = self._resolve_affected_hostnames(changed_records)
        if not affected:
            return

        # Note: It is a current design choice to do the more computationally expensive operation
        # of building the hosts objects every time from the resource record cache to keep simplicity
        # of reasoning about what the source of truth really is. If the performance of the scanner
        # ever becomes a true problem, then adding in a pre-built list of hosts to mutate as the
        # resource record cache changes will help a lot but requires being slightly more careful
        hosts = [self._build_host_data(iface, hostname) for iface, hostname in affected]

        updates = [h for h in hosts if h.addresses or h.services]
        removals = [h for h in hosts if not h.addresses and not h.services]

        if updates:
            self.server.send_cmd( ScannerResultsUpdate(results=[
                ScanResultItem(key=f"{h.interface}/{h.hostname}", result=h.model_dump()) for h in updates
            ]))
        if removals:
            self.server.send_cmd( ScannerResultsRemove(keys=[f"{h.interface}/{h.hostname}" for h in removals]))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scanner = MdnsScanner()
    # This fills out some basic information required to connect to the discovery server
    # It is done this way to enable the in-place re-exec style of privlege elevation
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
