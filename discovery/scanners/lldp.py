"""
LLDP scanner for the discovery server.

Listens passively for LLDP frames on active interfaces using a single raw
AF_PACKET socket. LLDP is link-local, so one entry per (interface, chassis_id)
is unique and stable — no multi-record resolution like mDNS requires.

Requires CAP_NET_RAW (or root).  The scanner connects and announces without
elevation; when the first interface is activated it attempts to open the raw
socket and calls reexec() if that fails with PermissionError.

Cache key: "{interface}/{chassis_id}"
"""
import argparse
import logging
import socket
import sys
import time
from select import select
from typing import Optional

from pydantic import BaseModel, ValidationError

from discovery.commands import (
    ScannerActiveInterfacesChanged,
    ScannerAnnounce,
    ScannerAvailableInterfacesChanged,
    ScannerResultsRemove,
    ScannerResultsUpdate,
    ScanResultItem,
    ServerClearCache,
    ServerSetActiveInterfaces,
    ServerStopScanner,
    ServerToScannerMessageAdapter,
    StatusResponse,
)
from discovery.scanners.base_scanner import BaseScanner
from scapy.layers.l2 import Ether
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUManagementAddress,
    LLDPDUPortDescription,
    LLDPDUPortID,
    LLDPDUSystemCapabilities,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)

ETH_P_LLDP = 0x88CC

logger = logging.getLogger("discovery.lldp")

# Maps scapy's per-bit enabled field names to human-readable capability labels.
_CAPABILITY_FIELDS: list[tuple[str, str]] = [
    ("other_enabled",               "other"),
    ("repeater_enabled",            "repeater"),
    ("mac_bridge_enabled",          "bridge"),
    ("wlan_access_point_enabled",   "wlan-ap"),
    ("router_enabled",              "router"),
    ("telephone_enabled",           "telephone"),
    ("docsis_cable_device_enabled", "docsis"),
    ("station_only_enabled",        "station"),
    ("two_port_mac_relay_enabled",  "two-port-mac-relay"),
    ("s_vlan_component_enabled",    "s-vlan-component"),
    ("c_vlan_component_enabled",    "c-vlan-component"),
]


def _format_id(subtype: int, family: int, id_val: str | bytes) -> str:
    """Format a Chassis ID or Port ID value as a human-readable string.

    For subtype 4 (MAC address) scapy already returns a formatted 'aa:bb:cc:dd:ee:ff'
    string.  For subtype 5 (network address) scapy exposes the IANA address family
    number in a separate 'family' field and the raw address bytes in 'id'.
    All other subtypes are decoded as UTF-8 or hex.
    """
    if isinstance(id_val, str):
        return id_val  # scapy already formatted it (e.g. MAC address)
    if subtype == 5:  # Network address — family is the IANA address family number
        try:
            if family == 1 and len(id_val) == 4:
                return socket.inet_ntop(socket.AF_INET, id_val)
            if family == 2 and len(id_val) == 16:
                return socket.inet_ntop(socket.AF_INET6, id_val)
        except OSError:
            pass
    try:
        return id_val.decode("utf-8")
    except UnicodeDecodeError:
        return id_val.hex()


def _decode_capabilities(cap_tlv: LLDPDUSystemCapabilities) -> list[str]:
    """Return the list of enabled capability labels from a System Capabilities TLV."""
    return [label for field, label in _CAPABILITY_FIELDS if getattr(cap_tlv, field, 0)]


def _decode_mgmt_address(tlv: LLDPDUManagementAddress) -> str:
    """Format a management address TLV value as a human-readable string."""
    subtype: int = tlv.management_address_subtype
    addr: bytes  = tlv.management_address
    try:
        if subtype == 1 and len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        if subtype == 2 and len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except OSError:
        pass
    return addr.hex()


class LLDPNeighborData(BaseModel):
    """
    A neighbor discovered via LLDP.
    Sent to the server as a scan result; also used as the internal cache entry.
    """
    interface: str                       # Interface this neighbor was seen on
    chassis_id: str                      # Chassis ID (formatted string)
    port_id: str                         # Port ID (formatted string)
    ttl: int                             # Hold time in seconds from the TTL TLV
    received_at: float                   # time.time() when this entry was last refreshed
    system_name: str = ""                # From System Name TLV
    system_description: str = ""        # From System Description TLV
    port_description: str = ""          # From Port Description TLV
    capabilities: list[str] = []        # Enabled capabilities, e.g. ['router', 'bridge']
    management_addresses: list[str] = []  # From Management Address TLVs


# Fields that constitute a real content change vs. a TTL-only refresh.
_CONTENT_FIELDS = frozenset({
    "port_id", "system_name", "system_description",
    "port_description", "capabilities", "management_addresses",
})


class LldpScanner(BaseScanner):
    def stop(self) -> None:
        self._keep_running = False

    def start(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(description="LLDP scanner")
        self._params = parser.parse_args(args)

        self.connect_to_server()
        if self.server is None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )

        self._available_interfaces: set[str] = {name for _, name in socket.if_nameindex()}
        self.server.send_cmd(ScannerAnnounce(
            name="lldp.v1",
            parameters=vars(self._params),
            interfaces=list(self._available_interfaces),
        ))
        self.wait_for_registration()

        self._active_interfaces: set[str] = set()
        self._cache: dict[str, LLDPNeighborData] = {}
        self._lldp_socket: Optional[socket.socket] = None
        self._keep_running = True

        try:
            while self._keep_running:
                read_list = [self.server]
                if self._lldp_socket is not None:
                    read_list.append(self._lldp_socket)
                ready, _, _ = select(read_list, [], [], 1.0)

                if self.server in ready:
                    self._handle_server_msgs()

                if self._lldp_socket is not None and self._lldp_socket in ready:
                    self._handle_lldp_packet()

                self._check_interfaces()
                self._expire_records(time.time())
        finally:
            if self._lldp_socket is not None:
                self._lldp_socket.close()

    def _open_socket(self) -> None:
        """
        Open the raw AF_PACKET socket for LLDP.
        Raises PermissionError if the process lacks CAP_NET_RAW.
        """
        self._lldp_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_LLDP)
        )

    def _join_interface(self, interface: str) -> None:
        if self._lldp_socket is None:
            try:
                self._open_socket()
            except PermissionError:
                logger.info("Insufficient privileges to open raw socket, re-execing with elevation")
                self.reexec()  # replaces this process; does not return
        self._active_interfaces.add(interface)
        logger.debug("Now listening for LLDP on %s", interface)

    def _leave_interface(self, interface: str) -> None:
        assert self.server is not None
        self._active_interfaces.discard(interface)
        logger.debug("Stopped listening for LLDP on %s", interface)
        removed_keys = [k for k in self._cache if k.startswith(f"{interface}/")]
        for key in removed_keys:
            del self._cache[key]
        if removed_keys:
            self.server.send_cmd( ScannerResultsRemove(keys=removed_keys))

    def _check_interfaces(self) -> None:
        assert self.server is not None
        current = {name for _, name in socket.if_nameindex()}
        if current == self._available_interfaces:
            return
        disappeared = self._available_interfaces - current

        active_changed = False
        for iface in disappeared:
            if iface in self._active_interfaces:
                self._leave_interface(iface)
                active_changed = True

        self._available_interfaces = current

        if active_changed:
            self.server.send_cmd( ScannerActiveInterfacesChanged(interfaces=list(self._active_interfaces)))
        self.server.send_cmd( ScannerAvailableInterfacesChanged(interfaces=list(self._available_interfaces)))

    def _expire_records(self, now: float) -> None:
        assert self.server is not None
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.received_at + entry.ttl < now
        ]
        for key in expired_keys:
            del self._cache[key]
        if expired_keys:
            logger.debug("Expired %d LLDP cache entries", len(expired_keys))
            self.server.send_cmd( ScannerResultsRemove(keys=expired_keys))

    def _clear_cache(self) -> None:
        assert self.server is not None
        keys = list(self._cache.keys())
        self._cache.clear()
        logger.info("Cache cleared, removing %d previously reported neighbors", len(keys))
        if keys:
            self.server.send_cmd( ScannerResultsRemove(keys=keys))

    def _handle_lldp_packet(self) -> None:
        assert self.server is not None
        assert self._lldp_socket is not None
        try:
            data, (ifname, _proto, _pkttype, _hatype, _addr) = self._lldp_socket.recvfrom(65535)
        except OSError:
            logger.warning("Error reading from LLDP socket", exc_info=True)
            return

        if ifname not in self._active_interfaces:
            return

        try:
            pkt = Ether(data)
        except Exception:
            logger.warning("[%s] Failed to parse LLDP frame, dropping", ifname, exc_info=True)
            return

        lldp = pkt.getlayer(LLDPDU)
        if lldp is None:
            return

        chassis_tlv: Optional[LLDPDUChassisID]   = lldp.getlayer(LLDPDUChassisID)
        port_tlv:    Optional[LLDPDUPortID]       = lldp.getlayer(LLDPDUPortID)
        ttl_tlv:     Optional[LLDPDUTimeToLive]   = lldp.getlayer(LLDPDUTimeToLive)

        if chassis_tlv is None or port_tlv is None or ttl_tlv is None:
            logger.warning("[%s] LLDPDU missing mandatory TLV(s), dropping", ifname)
            return

        chassis_id = _format_id(chassis_tlv.subtype, chassis_tlv.family, chassis_tlv.id)
        port_id    = _format_id(port_tlv.subtype, port_tlv.family, port_tlv.id)
        ttl        = ttl_tlv.ttl
        key        = f"{ifname}/{chassis_id}"

        logger.debug("[%s] LLDP from chassis=%r port=%r ttl=%d", ifname, chassis_id, port_id, ttl)

        if ttl == 0:
            # Shutdown LLDPDU — the neighbor is going offline.
            if key in self._cache:
                del self._cache[key]
                self.server.send_cmd( ScannerResultsRemove(keys=[key]))
            return

        # Optional TLVs
        sys_name_tlv:  Optional[LLDPDUSystemName]         = lldp.getlayer(LLDPDUSystemName)
        sys_desc_tlv:  Optional[LLDPDUSystemDescription]  = lldp.getlayer(LLDPDUSystemDescription)
        port_desc_tlv: Optional[LLDPDUPortDescription]    = lldp.getlayer(LLDPDUPortDescription)
        cap_tlv:       Optional[LLDPDUSystemCapabilities] = lldp.getlayer(LLDPDUSystemCapabilities)

        system_name  = sys_name_tlv.system_name.decode("utf-8", errors="replace") if sys_name_tlv else ""
        system_desc  = sys_desc_tlv.description.decode("utf-8", errors="replace")  if sys_desc_tlv  else ""
        port_desc    = port_desc_tlv.description.decode("utf-8", errors="replace") if port_desc_tlv else ""
        capabilities = _decode_capabilities(cap_tlv) if cap_tlv else []

        # Collect all Management Address TLVs (there may be more than one per LLDPDU).
        management_addresses: list[str] = []
        tlv = lldp
        while tlv is not None:
            if isinstance(tlv, LLDPDUManagementAddress):
                management_addresses.append(_decode_mgmt_address(tlv))
            if isinstance(tlv, LLDPDUEndOfLLDPDU):
                break
            tlv = tlv.payload if hasattr(tlv, "payload") else None

        now = time.time()
        neighbor = LLDPNeighborData(
            interface=ifname,
            chassis_id=chassis_id,
            port_id=port_id,
            ttl=ttl,
            received_at=now,
            system_name=system_name,
            system_description=system_desc,
            port_description=port_desc,
            capabilities=capabilities,
            management_addresses=management_addresses,
        )

        existing = self._cache.get(key)
        self._cache[key] = neighbor

        # Send an update only when content changed; a TTL-only refresh is silent.
        if existing is None or any(
            getattr(neighbor, f) != getattr(existing, f) for f in _CONTENT_FIELDS
        ):
            self.server.send_cmd( ScannerResultsUpdate(results=[ScanResultItem(key=key, result=neighbor.model_dump())]))

    def _handle_server_msgs(self) -> None:
        assert self.server is not None
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
                case ServerSetActiveInterfaces():
                    requested = set(cmd.interfaces)
                    for iface in requested - self._active_interfaces:
                        try:
                            self._join_interface(iface)
                        except OSError:
                            logger.warning("Failed to activate LLDP on %s", iface, exc_info=True)
                    for iface in self._active_interfaces - requested:
                        self._leave_interface(iface)
                    self.server.send_cmd( ScannerActiveInterfacesChanged(interfaces=list(self._active_interfaces)))

                case ServerClearCache():
                    logger.debug("clear_cache received")
                    self._clear_cache()

                case ServerStopScanner():
                    logger.info("stop_scanner received, shutting down")
                    self._keep_running = False

                case StatusResponse():
                    pass  # acknowledgement from server


if __name__ == "__main__":
    scanner = LldpScanner()
    extra_args = scanner.parse_connection_args(sys.argv[1:])
    scanner.start(extra_args)
