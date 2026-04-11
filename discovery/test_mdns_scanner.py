"""
Tests for discovery/scanners/mdns.py

Static unit tests exercise record processing, cache management, and host data
assembly without running the scanner's main loop. Integration tests start the
scanner in a thread and verify end-to-end behaviour by sending real mDNS UDP
packets to the bound address.
"""

import socket
import threading
import time
from argparse import Namespace
from collections import deque
from select import select
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.dns import DNS, DNSRR, DNSRRSRV

from discovery.client import DiscoveryClient
from discovery.server import DiscoveryServer
from discovery.scanners.mdns import (
    TYPE_A, TYPE_AAAA, TYPE_PTR, TYPE_SRV, TYPE_TXT,
    MDNSARecord, MDNSAAAARecord, MDNSPTRRecord, MDNSTXTRecord, MDNSSRVRecord,
    MdnsScanner,
)


# ---------------------------------------------------------------------------
# Protocol helpers (mirrors test_test_scanner.py)
# ---------------------------------------------------------------------------

_overflow: deque[dict] = deque()


def _send(sock, msg: dict) -> None:
    sock.send_msg(msg)


def _recv_one(sock, timeout: float = 5.0) -> dict:
    if _overflow:
        return _overflow.popleft()
    ready, _, _ = select([sock], [], [], timeout)
    if not ready:
        raise RuntimeError(f"Timed out after {timeout}s waiting for a message")
    msgs = sock.read_msgs()
    if not msgs:
        raise RuntimeError("Connection closed before a message was received")
    _overflow.extend(msgs[1:])
    return msgs[0]


def _send_and_expect(sock, msg: dict, expected_status: str = "accepted", timeout: float = 5.0) -> dict:
    _send(sock, msg)
    response = _recv_one(sock, timeout=timeout)
    assert response.get("status") == expected_status, (
        f"Expected status {expected_status!r}, got {response.get('status')!r}: {response}"
    )
    return response


def _drain(sock, timeout: float = 0.3) -> list[dict]:
    collected = list(_overflow)
    _overflow.clear()
    while True:
        ready, _, _ = select([sock], [], [], timeout)
        if not ready:
            break
        collected.extend(sock.read_msgs())
    return collected


def _find(msgs: list[dict], command: str, **fields) -> Optional[dict]:
    for msg in msgs:
        if msg.get("command") != command:
            continue
        if all(msg.get(k) == v for k, v in fields.items()):
            return msg
    return None


def _wait_for(sock, command: str, deadline_secs: float = 5.0, **fields) -> list[dict]:
    collected: list[dict] = []
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        collected += _drain(sock, timeout=0.3)
        if _find(collected, command, **fields):
            break
    return collected


# ---------------------------------------------------------------------------
# Record construction helpers
# ---------------------------------------------------------------------------

_NOW = 1_000_000.0  # Fixed timestamp used in unit tests


def _rr(rrname: bytes, rtype: int, ttl: int, rdata) -> SimpleNamespace:
    """Minimal DNSRecord-protocol-compatible object for use with _process_rr."""
    return SimpleNamespace(rrname=rrname, type=rtype, ttl=ttl, rdata=rdata)


def _srv_rr(rrname=b"My Service._http._tcp.local.", ttl=120, priority=0, weight=0, port=80, target=b"mydevice.local."):
    """SRV record mock — fields are direct attributes, not under rdata (mirrors DNSRRSRV)."""
    return SimpleNamespace(rrname=rrname, type=TYPE_SRV, ttl=ttl, priority=priority, weight=weight, port=port, target=target)


def _a(interface="eth0", rrname="mydevice.local.", address="192.168.1.1", ttl=120, received_at=_NOW):
    return MDNSARecord(interface=interface, rrname=rrname, address=address, ttl=ttl, received_at=received_at)


def _aaaa(interface="eth0", rrname="mydevice.local.", address="fe80::1", ttl=120, received_at=_NOW):
    return MDNSAAAARecord(interface=interface, rrname=rrname, address=address, ttl=ttl, received_at=received_at)


def _ptr(interface="eth0", rrname="_http._tcp.local.", target="My Service._http._tcp.local.", ttl=120, received_at=_NOW):
    return MDNSPTRRecord(interface=interface, rrname=rrname, target=target, ttl=ttl, received_at=received_at)


def _txt(interface="eth0", rrname="My Service._http._tcp.local.", entries=None, ttl=120, received_at=_NOW):
    return MDNSTXTRecord(interface=interface, rrname=rrname, entries=entries or ["path=/"], ttl=ttl, received_at=received_at)


def _srv(interface="eth0", rrname="My Service._http._tcp.local.", priority=0, weight=0, port=80, target="mydevice.local.", ttl=120, received_at=_NOW):
    return MDNSSRVRecord(interface=interface, rrname=rrname, priority=priority, weight=weight, port=port, target=target, ttl=ttl, received_at=received_at)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner_unit():
    """Bare MdnsScanner with mocked server and socket. Does not run start()."""
    s = MdnsScanner()
    s.server = MagicMock()
    s._record_cache = set()
    s._active_interfaces = set()
    s._mdns_listener = MagicMock()
    s._params = Namespace(multicast_group="ff02::fb", port=5353)
    return s


@pytest.fixture
def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def free_udp_port():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server_conn(free_tcp_port):
    _overflow.clear()
    server = DiscoveryServer()
    server_thread = threading.Thread(
        target=server.start,
        kwargs={"tcp_socket": ("127.0.0.1", free_tcp_port), "persistent": True},
        daemon=True,
    )
    server_thread.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", free_tcp_port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    conn = DiscoveryClient.connect(
        tcp_socket=("127.0.0.1", free_tcp_port),
        spawn_if_missing=False,
    )
    resp = _send_and_expect(conn, {"command": "announce", "type": "client"})
    assert "server_api_version" in resp
    yield conn
    conn.close()
    server.stop()
    server_thread.join(timeout=5.0)


@pytest.fixture
def mdns_scanner_thread(server_conn, free_tcp_port, free_udp_port):
    scanner = MdnsScanner()
    remaining = scanner.parse_connection_args([f"--tcp-socket=127.0.0.1:{free_tcp_port}"])
    thread = threading.Thread(
        target=scanner.start,
        args=(remaining + [
            f"--port={free_udp_port}",
            "--bind-address=::1",
            "--active-query-delay=999",
        ],),
        daemon=True,
    )
    thread.start()
    _wait_for(server_conn, "available_scanners_changed")
    _drain(server_conn, timeout=0.5)  # flush any residual fanout from startup
    yield scanner, free_udp_port
    _send_and_expect(server_conn, {"command": "stop_scanner", "scanner": "mdns.v1"})
    thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Integration packet helpers
# ---------------------------------------------------------------------------

_HOSTNAME = b"testhost.local."
_INSTANCE = b"My Service._http._tcp.local."
_SVC_TYPE  = b"_http._tcp.local."


def _build_response_packet() -> bytes:
    """Build a valid mDNS response with PTR, SRV, TXT, and AAAA records."""
    ptr  = DNSRR(rrname=_SVC_TYPE,  type="PTR",  ttl=120, rdata=_INSTANCE)
    srv  = DNSRRSRV(rrname=_INSTANCE, ttl=120, priority=0, weight=0, port=8080, target=_HOSTNAME)
    txt  = DNSRR(rrname=_INSTANCE,  type="TXT",  ttl=120, rdata=[b"path=/test"])
    aaaa = DNSRR(rrname=_HOSTNAME,  type="AAAA", ttl=120, rdata="fe80::1")
    return bytes(DNS(qr=1, aa=1, ancount=4, an=ptr / srv / txt / aaaa))


def _build_goodbye_packet() -> bytes:
    """Build TTL=0 goodbye packets for all records from _build_response_packet."""
    ptr  = DNSRR(rrname=_SVC_TYPE,  type="PTR",  ttl=0, rdata=_INSTANCE)
    srv  = DNSRRSRV(rrname=_INSTANCE, ttl=0, priority=0, weight=0, port=8080, target=_HOSTNAME)
    txt  = DNSRR(rrname=_INSTANCE,  type="TXT",  ttl=0, rdata=[b"path=/test"])
    aaaa = DNSRR(rrname=_HOSTNAME,  type="AAAA", ttl=0, rdata="fe80::1")
    return bytes(DNS(qr=1, aa=1, ancount=4, an=ptr / srv / txt / aaaa))


def _send_mdns_packet(udp_port: int, pkt_bytes: bytes) -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::1", 0))
        s.sendto(pkt_bytes, ("::1", udp_port))


# ---------------------------------------------------------------------------
# TestProcessRR
# ---------------------------------------------------------------------------

class TestProcessRR:
    def test_new_a_record_added(self, scanner_unit):
        rr = _rr(b"mydevice.local.", TYPE_A, 120, "192.168.1.1")
        result = scanner_unit._process_rr("eth0", rr, _NOW)
        assert isinstance(result, MDNSARecord)
        assert result.rrname == "mydevice.local."
        assert result.interface == "eth0"
        assert len(scanner_unit._record_cache) == 1

    def test_ttl_refresh_returns_none(self, scanner_unit):
        rr = _rr(b"mydevice.local.", TYPE_A, 120, "192.168.1.1")
        scanner_unit._process_rr("eth0", rr, _NOW)
        result = scanner_unit._process_rr("eth0", rr, _NOW + 60)
        assert result is None
        assert len(scanner_unit._record_cache) == 1

    def test_goodbye_removes_existing(self, scanner_unit):
        rr = _rr(b"mydevice.local.", TYPE_A, 120, "192.168.1.1")
        scanner_unit._process_rr("eth0", rr, _NOW)
        goodbye = _rr(b"mydevice.local.", TYPE_A, 0, "192.168.1.1")
        result = scanner_unit._process_rr("eth0", goodbye, _NOW + 1)
        assert isinstance(result, MDNSARecord)
        assert result.rrname == "mydevice.local."
        assert result.interface == "eth0"
        assert len(scanner_unit._record_cache) == 0

    def test_goodbye_unseen_returns_none(self, scanner_unit):
        goodbye = _rr(b"ghost.local.", TYPE_A, 0, "10.0.0.1")
        result = scanner_unit._process_rr("eth0", goodbye, _NOW)
        assert result is None
        assert len(scanner_unit._record_cache) == 0

    def test_ptr_returns_service_type(self, scanner_unit):
        rr = _rr(b"_http._tcp.local.", TYPE_PTR, 120, b"My Service._http._tcp.local.")
        result = scanner_unit._process_rr("eth0", rr, _NOW)
        assert isinstance(result, MDNSPTRRecord)
        assert result.rrname == "_http._tcp.local."

    def test_srv_returns_instance_name(self, scanner_unit):
        rr = _srv_rr()
        result = scanner_unit._process_rr("eth0", rr, _NOW)
        assert isinstance(result, MDNSSRVRecord)
        assert result.rrname == "My Service._http._tcp.local."

    def test_txt_content_change_detected(self, scanner_unit):
        rr1 = _rr(b"My Service._http._tcp.local.", TYPE_TXT, 120, [b"path=/old"])
        scanner_unit._process_rr("eth0", rr1, _NOW)
        rr2 = _rr(b"My Service._http._tcp.local.", TYPE_TXT, 120, [b"path=/new"])
        result = scanner_unit._process_rr("eth0", rr2, _NOW + 1)
        assert isinstance(result, MDNSTXTRecord)
        assert result.rrname == "My Service._http._tcp.local."

    def test_txt_ttl_refresh_silent(self, scanner_unit):
        rr = _rr(b"My Service._http._tcp.local.", TYPE_TXT, 120, [b"path=/"])
        scanner_unit._process_rr("eth0", rr, _NOW)
        result = scanner_unit._process_rr("eth0", rr, _NOW + 60)
        assert result is None

    def test_srv_content_change_detected(self, scanner_unit):
        scanner_unit._process_rr("eth0", _srv_rr(port=80), _NOW)
        result = scanner_unit._process_rr("eth0", _srv_rr(port=8080), _NOW + 1)
        assert isinstance(result, MDNSSRVRecord)
        assert result.rrname == "My Service._http._tcp.local."

    def test_unsupported_type_returns_none(self, scanner_unit):
        rr = _rr(b"weird.local.", 99, 120, b"whatever")
        result = scanner_unit._process_rr("eth0", rr, _NOW)
        assert result is None
        assert len(scanner_unit._record_cache) == 0


# ---------------------------------------------------------------------------
# TestExpireRecords
# ---------------------------------------------------------------------------

class TestExpireRecords:
    def test_expired_records_removed(self, scanner_unit):
        scanner_unit._record_cache.add(_a(ttl=10, received_at=_NOW - 20))  # expired
        scanner_unit._record_cache.add(_a(rrname="other.local.", ttl=120, received_at=_NOW))  # live
        expired = scanner_unit._expire_records(_NOW)
        assert len(scanner_unit._record_cache) == 1
        assert len(expired) == 1

    def test_live_records_kept(self, scanner_unit):
        scanner_unit._record_cache.add(_a(ttl=120, received_at=_NOW))
        expired = scanner_unit._expire_records(_NOW + 60)
        assert len(scanner_unit._record_cache) == 1
        assert len(expired) == 0

    def test_returns_correct_rrname_types(self, scanner_unit):
        t = _NOW - 1000  # all expired
        scanner_unit._record_cache = {
            _a(rrname="host.local.", ttl=1, received_at=t),
            _aaaa(rrname="host.local.", ttl=1, received_at=t),
            _ptr(ttl=1, received_at=t),
            _txt(ttl=1, received_at=t),
            _srv(ttl=1, received_at=t),
        }
        expired = scanner_unit._expire_records(_NOW)
        record_types = {type(r) for r in expired}
        assert MDNSARecord in record_types or MDNSAAAARecord in record_types  # hostname records
        assert MDNSPTRRecord in record_types                                  # service type records
        assert MDNSSRVRecord in record_types or MDNSTXTRecord in record_types # instance name records

    def test_empty_cache_returns_empty_set(self, scanner_unit):
        result = scanner_unit._expire_records(_NOW)
        assert result == set()


# ---------------------------------------------------------------------------
# TestResolveAffectedHostnames
# ---------------------------------------------------------------------------

class TestResolveAffectedHostnames:
    def test_hostname_resolves_directly(self, scanner_unit):
        changed = {_a(interface="eth0", rrname="mydevice.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == {("eth0", "mydevice.local.")}

    def test_instance_name_follows_srv(self, scanner_unit):
        scanner_unit._record_cache.add(_srv(interface="eth0", target="mydevice.local."))
        changed = {_txt(interface="eth0", rrname="My Service._http._tcp.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == {("eth0", "mydevice.local.")}

    def test_service_type_follows_ptr_then_srv(self, scanner_unit):
        scanner_unit._record_cache = {
            _ptr(interface="eth0"),
            _srv(interface="eth0", target="mydevice.local."),
        }
        changed = {_ptr(interface="eth0", rrname="_http._tcp.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == {("eth0", "mydevice.local.")}

    def test_instance_name_no_srv_returns_empty(self, scanner_unit):
        changed = {_txt(interface="eth0", rrname="My Service._http._tcp.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == set()

    def test_service_type_no_ptr_returns_empty(self, scanner_unit):
        changed = {_ptr(interface="eth0", rrname="_http._tcp.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == set()

    def test_interface_scoped(self, scanner_unit):
        scanner_unit._record_cache = {
            _srv(interface="eth0",  rrname="Svc._http._tcp.local.", target="host.local."),
            _srv(interface="wlan0", rrname="Svc._http._tcp.local.", target="host.local."),
        }
        changed = {_txt(interface="eth0", rrname="Svc._http._tcp.local.")}
        result = scanner_unit._resolve_affected_hostnames(changed)
        assert result == {("eth0", "host.local.")}


# ---------------------------------------------------------------------------
# TestBuildHostData
# ---------------------------------------------------------------------------

class TestBuildHostData:
    def test_addresses_from_a_records(self, scanner_unit):
        scanner_unit._record_cache.add(_a(address="192.168.1.1"))
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert "192.168.1.1" in host.addresses

    def test_addresses_from_aaaa_records(self, scanner_unit):
        scanner_unit._record_cache.add(_aaaa(address="fe80::1"))
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert "fe80::1" in host.addresses

    def test_service_built_from_srv_ptr_txt(self, scanner_unit):
        scanner_unit._record_cache = {_ptr(), _srv(port=8080), _txt(entries=["path=/api"])}
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert len(host.services) == 1
        svc = host.services[0]
        assert svc.port == 8080
        assert svc.service_type == "_http._tcp.local."
        assert svc.txt.get("path") == "/api"

    def test_service_skipped_without_ptr(self, scanner_unit):
        scanner_unit._record_cache = {_srv()}  # no matching PTR
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert len(host.services) == 0

    def test_txt_key_value_parsed(self, scanner_unit):
        scanner_unit._record_cache = {_ptr(), _srv(), _txt(entries=["version=1.0", "color=T"])}
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert host.services[0].txt == {"version": "1.0", "color": "T"}

    def test_txt_key_no_value(self, scanner_unit):
        scanner_unit._record_cache = {_ptr(), _srv(), _txt(entries=["flag"])}
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert host.services[0].txt == {"flag": ""}

    def test_empty_cache_returns_empty_host(self, scanner_unit):
        host = scanner_unit._build_host_data("eth0", "mydevice.local.")
        assert host.addresses == []
        assert host.services == []


# ---------------------------------------------------------------------------
# TestClearCache
# ---------------------------------------------------------------------------

class TestClearCache:
    def test_records_cleared(self, scanner_unit):
        scanner_unit._record_cache = {_a(), _aaaa(), _ptr()}
        scanner_unit._clear_cache()
        assert len(scanner_unit._record_cache) == 0

    def test_scan_results_remove_sent(self, scanner_unit):
        scanner_unit._record_cache = {_a()}
        scanner_unit._clear_cache()
        scanner_unit.server.send_msg.assert_called_once()
        msg = scanner_unit.server.send_msg.call_args[0][0]
        assert msg["command"] == "scan_results_remove"
        assert "eth0/mydevice.local." in msg["keys"]

    def test_keys_include_srv_targets(self, scanner_unit):
        scanner_unit._record_cache = {_srv(target="mydevice.local.")}
        scanner_unit._clear_cache()
        msg = scanner_unit.server.send_msg.call_args[0][0]
        assert "eth0/mydevice.local." in msg["keys"]

    def test_empty_cache_no_message(self, scanner_unit):
        scanner_unit._clear_cache()
        scanner_unit.server.send_msg.assert_not_called()


# ---------------------------------------------------------------------------
# TestLeaveInterface
# ---------------------------------------------------------------------------

class TestLeaveInterface:
    def test_records_for_interface_removed(self, scanner_unit):
        scanner_unit._record_cache = {
            _a(interface="eth0"),
            _a(interface="wlan0", rrname="other.local."),
        }
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        assert all(r.interface != "eth0" for r in scanner_unit._record_cache)

    def test_other_interface_records_preserved(self, scanner_unit):
        scanner_unit._record_cache = {
            _a(interface="eth0"),
            _a(interface="wlan0", rrname="other.local."),
        }
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        assert any(r.interface == "wlan0" for r in scanner_unit._record_cache)

    def test_scan_results_remove_sent(self, scanner_unit):
        scanner_unit._record_cache = {_a(interface="eth0")}
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        scanner_unit.server.send_msg.assert_called_once()
        msg = scanner_unit.server.send_msg.call_args[0][0]
        assert msg["command"] == "scan_results_remove"
        assert "eth0/mydevice.local." in msg["keys"]

    def test_empty_interface_no_message(self, scanner_unit):
        scanner_unit._record_cache = {_a(interface="wlan0", rrname="other.local.")}
        with patch("socket.if_nametoindex", return_value=1):
            scanner_unit._leave_interface("eth0")
        scanner_unit.server.send_msg.assert_not_called()


# ---------------------------------------------------------------------------
# TestMdnsIntegration
# ---------------------------------------------------------------------------

class TestMdnsIntegration:
    def test_scanner_registered(self, server_conn, mdns_scanner_thread):
        resp = _send_and_expect(server_conn, {"command": "get_registered_scanners"})
        names = [s.get("name") for s in resp.get("scanners", [])]
        assert "mdns.v1" in names

    def test_full_packet_produces_host_update(self, server_conn, mdns_scanner_thread):
        _, udp_port = mdns_scanner_thread
        _drain(server_conn, timeout=0.3)

        _send_mdns_packet(udp_port, _build_response_packet())

        msgs = _wait_for(server_conn, "scan_results_update", deadline_secs=5.0, scanner="mdns.v1")
        update = _find(msgs, "scan_results_update", scanner="mdns.v1")
        assert update is not None, f"scan_results_update not received; got: {msgs}"

        results = update.get("results", [])
        lo_key = "lo/testhost.local."
        host_result = next((r for r in results if r.get("key") == lo_key), None)
        assert host_result is not None, f"Key {lo_key!r} not found; keys were: {[r.get('key') for r in results]}"

        host = host_result["result"]
        assert host["hostname"] == "testhost.local."
        assert "fe80::1" in host["addresses"]
        assert len(host["services"]) == 1
        assert host["services"][0]["port"] == 8080

    def test_goodbye_packet_produces_remove(self, server_conn, mdns_scanner_thread):
        _, udp_port = mdns_scanner_thread
        _drain(server_conn, timeout=0.3)

        # Seed the cache independently — don't rely on a prior test having done it.
        _send_mdns_packet(udp_port, _build_response_packet())
        _wait_for(server_conn, "scan_results_update", deadline_secs=5.0, scanner="mdns.v1")
        _drain(server_conn, timeout=0.3)

        _send_mdns_packet(udp_port, _build_goodbye_packet())

        msgs = _wait_for(server_conn, "scan_results_remove", deadline_secs=5.0, scanner="mdns.v1")
        remove = _find(msgs, "scan_results_remove", scanner="mdns.v1")
        assert remove is not None, f"scan_results_remove not received; got: {msgs}"
        assert "lo/testhost.local." in remove.get("keys", [])
