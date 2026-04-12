"""
Tests for discovery/scanners/lldp.py

# ---- Implementation notes / things to verify against real hardware --------
#
# Scapy field names (confirmed against scapy 2.7 installed on this system):
#   LLDPDUTimeToLive        → .ttl          (NOT .seconds)
#   LLDPDUChassisID/PortID  → .subtype, .family, .id
#       For subtype 4 (MAC), scapy returns a pre-formatted str 'aa:bb:cc:dd:ee:ff'.
#       For subtype 5 (network address), .family = IANA family, .id = raw address bytes.
#       All other subtypes return bytes in .id.
#   LLDPDUSystemCapabilities uses individual bit fields (router_enabled, mac_bridge_enabled,
#       etc.) rather than a single enabled_capabilities integer field.
#   LLDPDUManagementAddress → .management_address_subtype (1=IPv4, 2=IPv6),
#                              .management_address (raw bytes)
#
# Management address TLV iteration uses the scapy payload chain.
# If scapy moves LLDP to PacketListField (as it did for DNS in 2.7), the
# while-loop in _handle_lldp_packet will break. Fix mirrors the mDNS fix.
#
# Integration tests require AF_PACKET (CAP_NET_RAW / root) and are skipped
# in unprivileged environments. Run as root or with cap_net_raw to exercise them.
#
# reexec() flow: on PermissionError when opening the raw socket the process is
# replaced via sudo. The server detects the disconnect and removes the scanner;
# the elevated process reconnects and re-announces. There is a brief window
# where clients see the scanner absent.
# ---------------------------------------------------------------------------
"""

import os
import socket
import threading
import time
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest
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
from scapy.layers.l2 import Ether

from discovery.scanners.lldp import (
    ETH_P_LLDP,
    LLDPNeighborData,
    LldpScanner,
    _decode_capabilities,
    _decode_mgmt_address,
    _format_id,
)

# ---------------------------------------------------------------------------
# Frame construction helpers
# ---------------------------------------------------------------------------

_CHASSIS_MAC_BYTES = b"\xaa\xbb\xcc\xdd\xee\xff"
_CHASSIS_MAC_STR   = "aa:bb:cc:dd:ee:ff"
_PORT_ID_BYTES     = b"GigabitEthernet0/0"
_PORT_ID_STR       = "GigabitEthernet0/0"
_IFNAME            = "eth0"
_NOW               = 1_000_000.0

# AF_PACKET recvfrom address tuple: (ifname, proto, pkttype, hatype, addr)
_RECVFROM_ADDR = (_IFNAME, ETH_P_LLDP, 4, 1, _CHASSIS_MAC_BYTES)


def _build_lldp_frame(
    chassis_mac: bytes = _CHASSIS_MAC_BYTES,
    chassis_subtype: int = 4,
    port_id: bytes = _PORT_ID_BYTES,
    port_subtype: int = 5,
    ttl: int = 120,
    system_name: bytes = b"testdevice",
    system_desc: bytes = b"Test Device 1.0",
    port_desc: bytes = b"GigabitEthernet0/0",
    router_enabled: int = 0,
    bridge_enabled: int = 0,
    mgmt_addresses: list[tuple[int, bytes]] | None = None,
    include_system_name: bool = True,
    include_system_desc: bool = True,
    include_port_desc: bool = True,
    include_capabilities: bool = False,
) -> bytes:
    """Build a complete LLDP Ethernet frame as bytes."""
    pkt = (
        Ether(dst="01:80:c2:00:00:0e", src="00:11:22:33:44:55", type=ETH_P_LLDP)
        / LLDPDU()
        / LLDPDUChassisID(subtype=chassis_subtype, id=chassis_mac)
        / LLDPDUPortID(subtype=port_subtype, id=port_id)
        / LLDPDUTimeToLive(ttl=ttl)
    )
    if include_system_name:
        pkt /= LLDPDUSystemName(system_name=system_name)
    if include_system_desc:
        pkt /= LLDPDUSystemDescription(description=system_desc)
    if include_port_desc:
        pkt /= LLDPDUPortDescription(description=port_desc)
    if include_capabilities:
        pkt /= LLDPDUSystemCapabilities(
            router_available=router_enabled,
            router_enabled=router_enabled,
            mac_bridge_available=bridge_enabled,
            mac_bridge_enabled=bridge_enabled,
        )
    for subtype, addr in (mgmt_addresses or []):
        pkt /= LLDPDUManagementAddress(
            management_address_subtype=subtype,
            management_address=addr,
        )
    pkt /= LLDPDUEndOfLLDPDU()
    return bytes(pkt)


def _build_shutdown_frame() -> bytes:
    """Build a TTL=0 shutdown LLDPDU."""
    return _build_lldp_frame(
        ttl=0,
        include_system_name=False,
        include_system_desc=False,
        include_port_desc=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner_unit():
    """Bare LldpScanner with mocked server and socket. Does not run start()."""
    s = LldpScanner()
    s.server = MagicMock()
    s._cache = {}
    s._active_interfaces = {_IFNAME}
    s._lldp_socket = MagicMock()
    s._params = Namespace()
    return s


def _make_neighbor(
    interface: str = _IFNAME,
    chassis_id: str = _CHASSIS_MAC_STR,
    port_id: str = _PORT_ID_STR,
    ttl: int = 120,
    received_at: float = _NOW,
    system_name: str = "testdevice",
    **kwargs,
) -> LLDPNeighborData:
    return LLDPNeighborData(
        interface=interface,
        chassis_id=chassis_id,
        port_id=port_id,
        ttl=ttl,
        received_at=received_at,
        system_name=system_name,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# TestFormatId
# ---------------------------------------------------------------------------

class TestFormatId:
    def test_mac_subtype_returns_string(self):
        # scapy returns a pre-formatted str for subtype 4
        assert _format_id(4, 0, "aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_ipv4_network_address(self):
        addr = socket.inet_pton(socket.AF_INET, "192.168.1.1")
        assert _format_id(5, 1, addr) == "192.168.1.1"

    def test_ipv6_network_address(self):
        addr = socket.inet_pton(socket.AF_INET6, "fe80::1")
        assert _format_id(5, 2, addr) == "fe80::1"

    def test_interface_name_decoded_utf8(self):
        assert _format_id(6, 0, b"eth0") == "eth0"

    def test_non_utf8_falls_back_to_hex(self):
        result = _format_id(7, 0, b"\xff\xfe")
        assert result == "fffe"

    def test_local_string(self):
        assert _format_id(7, 0, b"custom-id") == "custom-id"


# ---------------------------------------------------------------------------
# TestDecodeCapabilities
# ---------------------------------------------------------------------------

class TestDecodeCapabilities:
    def _make_cap_tlv(self, **fields) -> LLDPDUSystemCapabilities:
        return LLDPDUSystemCapabilities(**fields)

    def test_no_capabilities(self):
        assert _decode_capabilities(self._make_cap_tlv()) == []

    def test_router_only(self):
        caps = _decode_capabilities(self._make_cap_tlv(router_enabled=1))
        assert caps == ["router"]

    def test_multiple_capabilities(self):
        caps = _decode_capabilities(self._make_cap_tlv(router_enabled=1, mac_bridge_enabled=1))
        assert "router" in caps
        assert "bridge" in caps

    def test_all_common_capabilities(self):
        cap = self._make_cap_tlv(
            router_enabled=1,
            mac_bridge_enabled=1,
            telephone_enabled=1,
            wlan_access_point_enabled=1,
        )
        caps = _decode_capabilities(cap)
        assert set(caps) == {"router", "bridge", "telephone", "wlan-ap"}


# ---------------------------------------------------------------------------
# TestDecodeManagementAddress
# ---------------------------------------------------------------------------

class TestDecodeManagementAddress:
    def _make_mgmt_tlv(self, subtype: int, addr: bytes) -> LLDPDUManagementAddress:
        return LLDPDUManagementAddress(management_address_subtype=subtype, management_address=addr)

    def test_ipv4_address(self):
        addr = socket.inet_pton(socket.AF_INET, "10.0.0.1")
        assert _decode_mgmt_address(self._make_mgmt_tlv(1, addr)) == "10.0.0.1"

    def test_ipv6_address(self):
        addr = socket.inet_pton(socket.AF_INET6, "fe80::1")
        assert _decode_mgmt_address(self._make_mgmt_tlv(2, addr)) == "fe80::1"

    def test_unknown_subtype_returns_hex(self):
        result = _decode_mgmt_address(self._make_mgmt_tlv(99, b"\xde\xad"))
        assert result == "dead"


# ---------------------------------------------------------------------------
# TestHandleLldpPacket
# ---------------------------------------------------------------------------

class TestHandleLldpPacket:
    def _feed(self, scanner, frame: bytes, ifname: str = _IFNAME):
        scanner._lldp_socket.recvfrom.return_value = (frame, (ifname, ETH_P_LLDP, 4, 1, b""))

    def test_new_neighbor_added_to_cache(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame())
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        assert f"{_IFNAME}/{_CHASSIS_MAC_STR}" in scanner_unit._cache

    def test_scan_results_update_sent(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame())
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        scanner_unit.server.send_cmd.assert_called_once()
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert model.command == "scan_results_update"
        assert model.results[0].key == f"{_IFNAME}/{_CHASSIS_MAC_STR}"

    def test_ttl_refresh_does_not_send_update(self, scanner_unit):
        frame = _build_lldp_frame()
        with patch("time.time", return_value=_NOW):
            self._feed(scanner_unit, frame)
            scanner_unit._handle_lldp_packet()
            scanner_unit.server.send_cmd.reset_mock()
            self._feed(scanner_unit, frame)
            scanner_unit._handle_lldp_packet()
        scanner_unit.server.send_cmd.assert_not_called()

    def test_content_change_sends_update(self, scanner_unit):
        with patch("time.time", return_value=_NOW):
            self._feed(scanner_unit, _build_lldp_frame(system_name=b"device-v1"))
            scanner_unit._handle_lldp_packet()
            scanner_unit.server.send_cmd.reset_mock()
            self._feed(scanner_unit, _build_lldp_frame(system_name=b"device-v2"))
            scanner_unit._handle_lldp_packet()
        scanner_unit.server.send_cmd.assert_called_once()

    def test_shutdown_ttl0_removes_from_cache(self, scanner_unit):
        with patch("time.time", return_value=_NOW):
            self._feed(scanner_unit, _build_lldp_frame())
            scanner_unit._handle_lldp_packet()
            scanner_unit.server.send_cmd.reset_mock()
            self._feed(scanner_unit, _build_shutdown_frame())
            scanner_unit._handle_lldp_packet()
        assert f"{_IFNAME}/{_CHASSIS_MAC_STR}" not in scanner_unit._cache
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert model.command == "scan_results_remove"
        assert f"{_IFNAME}/{_CHASSIS_MAC_STR}" in model.keys

    def test_shutdown_unseen_neighbor_silent(self, scanner_unit):
        self._feed(scanner_unit, _build_shutdown_frame())
        scanner_unit._handle_lldp_packet()
        scanner_unit.server.send_cmd.assert_not_called()

    def test_inactive_interface_ignored(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame(), ifname="wlan0")
        scanner_unit._handle_lldp_packet()
        assert scanner_unit._cache == {}
        scanner_unit.server.send_cmd.assert_not_called()

    def test_malformed_frame_does_not_crash(self, scanner_unit):
        scanner_unit._lldp_socket.recvfrom.return_value = (b"\xff\xff\xff garbage", _RECVFROM_ADDR)
        scanner_unit._handle_lldp_packet()  # must not raise
        assert scanner_unit._cache == {}

    def test_system_name_parsed(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame(system_name=b"my-switch"))
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        entry = scanner_unit._cache[f"{_IFNAME}/{_CHASSIS_MAC_STR}"]
        assert entry.system_name == "my-switch"

    def test_capabilities_parsed(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame(
            include_capabilities=True, router_enabled=1
        ))
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        entry = scanner_unit._cache[f"{_IFNAME}/{_CHASSIS_MAC_STR}"]
        assert "router" in entry.capabilities

    def test_management_address_parsed(self, scanner_unit):
        ipv4 = socket.inet_pton(socket.AF_INET, "192.168.1.1")
        self._feed(scanner_unit, _build_lldp_frame(mgmt_addresses=[(1, ipv4)]))
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        entry = scanner_unit._cache[f"{_IFNAME}/{_CHASSIS_MAC_STR}"]
        assert "192.168.1.1" in entry.management_addresses

    def test_multiple_management_addresses(self, scanner_unit):
        ipv4 = socket.inet_pton(socket.AF_INET, "10.0.0.1")
        ipv6 = socket.inet_pton(socket.AF_INET6, "fe80::1")
        self._feed(scanner_unit, _build_lldp_frame(mgmt_addresses=[(1, ipv4), (2, ipv6)]))
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        entry = scanner_unit._cache[f"{_IFNAME}/{_CHASSIS_MAC_STR}"]
        assert "10.0.0.1" in entry.management_addresses
        assert "fe80::1" in entry.management_addresses

    def test_no_optional_tlvs_still_creates_entry(self, scanner_unit):
        self._feed(scanner_unit, _build_lldp_frame(
            include_system_name=False,
            include_system_desc=False,
            include_port_desc=False,
        ))
        with patch("time.time", return_value=_NOW):
            scanner_unit._handle_lldp_packet()
        entry = scanner_unit._cache[f"{_IFNAME}/{_CHASSIS_MAC_STR}"]
        assert entry.system_name == ""
        assert entry.system_description == ""
        assert entry.port_description == ""


# ---------------------------------------------------------------------------
# TestExpireRecords
# ---------------------------------------------------------------------------

class TestExpireRecords:
    def test_expired_entry_removed(self, scanner_unit):
        scanner_unit._cache["eth0/old"] = _make_neighbor(
            chassis_id="old", ttl=10, received_at=_NOW - 20
        )
        scanner_unit._expire_records(_NOW)
        assert "eth0/old" not in scanner_unit._cache

    def test_live_entry_kept(self, scanner_unit):
        key = f"{_IFNAME}/{_CHASSIS_MAC_STR}"
        scanner_unit._cache[key] = _make_neighbor(ttl=120, received_at=_NOW)
        scanner_unit._expire_records(_NOW + 60)
        assert key in scanner_unit._cache

    def test_scan_results_remove_sent_for_expired(self, scanner_unit):
        scanner_unit._cache["eth0/gone"] = _make_neighbor(
            chassis_id="gone", ttl=5, received_at=_NOW - 10
        )
        scanner_unit._expire_records(_NOW)
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert model.command == "scan_results_remove"
        assert "eth0/gone" in model.keys

    def test_no_message_when_nothing_expired(self, scanner_unit):
        scanner_unit._cache["eth0/live"] = _make_neighbor(ttl=120, received_at=_NOW)
        scanner_unit._expire_records(_NOW + 60)
        scanner_unit.server.send_cmd.assert_not_called()

    def test_empty_cache_no_message(self, scanner_unit):
        scanner_unit._expire_records(_NOW)
        scanner_unit.server.send_cmd.assert_not_called()

    def test_boundary_not_yet_expired(self, scanner_unit):
        # received_at=T, ttl=10: expires when now > T+10, not at T+10 exactly
        scanner_unit._cache["eth0/boundary"] = _make_neighbor(
            chassis_id="boundary", ttl=10, received_at=_NOW
        )
        scanner_unit._expire_records(_NOW + 10)  # exactly at boundary — still live
        assert "eth0/boundary" in scanner_unit._cache

    def test_boundary_just_past_expired(self, scanner_unit):
        scanner_unit._cache["eth0/boundary"] = _make_neighbor(
            chassis_id="boundary", ttl=10, received_at=_NOW
        )
        scanner_unit._expire_records(_NOW + 10 + 0.001)
        assert "eth0/boundary" not in scanner_unit._cache


# ---------------------------------------------------------------------------
# TestLeaveInterface
# ---------------------------------------------------------------------------

class TestLeaveInterface:
    def test_records_for_interface_removed(self, scanner_unit):
        scanner_unit._cache[f"eth0/{_CHASSIS_MAC_STR}"] = _make_neighbor(interface="eth0")
        scanner_unit._cache["wlan0/other"] = _make_neighbor(interface="wlan0", chassis_id="other")
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        assert all(not k.startswith("eth0/") for k in scanner_unit._cache)

    def test_other_interface_records_preserved(self, scanner_unit):
        scanner_unit._cache[f"eth0/{_CHASSIS_MAC_STR}"] = _make_neighbor(interface="eth0")
        scanner_unit._cache["wlan0/other"] = _make_neighbor(interface="wlan0", chassis_id="other")
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        assert "wlan0/other" in scanner_unit._cache

    def test_scan_results_remove_sent(self, scanner_unit):
        key = f"eth0/{_CHASSIS_MAC_STR}"
        scanner_unit._cache[key] = _make_neighbor(interface="eth0")
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert model.command == "scan_results_remove"
        assert key in model.keys

    def test_empty_interface_no_message(self, scanner_unit):
        scanner_unit._cache["wlan0/other"] = _make_neighbor(interface="wlan0", chassis_id="other")
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        scanner_unit.server.send_cmd.assert_not_called()

    def test_interface_removed_from_active_set(self, scanner_unit):
        scanner_unit._active_interfaces.add("eth0")
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        assert "eth0" not in scanner_unit._active_interfaces


# ---------------------------------------------------------------------------
# TestClearCache
# ---------------------------------------------------------------------------

class TestClearCache:
    def test_cache_emptied(self, scanner_unit):
        scanner_unit._cache["eth0/a"] = _make_neighbor(chassis_id="a")
        scanner_unit._cache["eth0/b"] = _make_neighbor(chassis_id="b")
        scanner_unit._clear_cache()
        assert scanner_unit._cache == {}

    def test_scan_results_remove_sent(self, scanner_unit):
        scanner_unit._cache["eth0/a"] = _make_neighbor(chassis_id="a")
        scanner_unit._clear_cache()
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert model.command == "scan_results_remove"
        assert "eth0/a" in model.keys

    def test_all_keys_included(self, scanner_unit):
        scanner_unit._cache["eth0/a"] = _make_neighbor(chassis_id="a")
        scanner_unit._cache["eth0/b"] = _make_neighbor(chassis_id="b")
        scanner_unit._clear_cache()
        model = scanner_unit.server.send_cmd.call_args[0][0]
        assert set(model.keys) == {"eth0/a", "eth0/b"}

    def test_empty_cache_no_message(self, scanner_unit):
        scanner_unit._clear_cache()
        scanner_unit.server.send_cmd.assert_not_called()


# ---------------------------------------------------------------------------
# Integration tests (require CAP_NET_RAW / root)
# ---------------------------------------------------------------------------

pytestmark_root = pytest.mark.skipif(
    os.getuid() != 0,
    reason="LLDP integration tests require CAP_NET_RAW (run as root)",
)


@pytestmark_root
class TestLldpIntegration:
    """
    End-to-end tests that open a real AF_PACKET socket and inject frames via
    a second raw socket on the loopback interface.  Requires root.
    """
    pass
