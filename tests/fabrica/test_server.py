"""
Tests for discovery/server.py and discovery/client.py

Covers:
- DiscoveryClient.spawn_if_missing behaviour
- Server lifecycle (persistent vs non-persistent)
- Announce handshake for clients and scanners
- All client-command → server-response paths
- Scanner message handling and result storage
- Multi-client fanout broadcasts
"""

import socket
import threading
import time
from collections import deque
from select import select
from typing import Optional

import pytest

from fabrica.discovery.client import DiscoveryClient
from fabrica.discovery.server import DiscoveryServer


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

_overflow: deque[dict] = deque()


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
    sock.send_msg(msg)
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


def _wait_for(sock, command: str, deadline_secs: float = 5.0, **fields) -> list[dict]:
    collected: list[dict] = []
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        collected += _drain(sock, timeout=0.3)
        if _find(collected, command, **fields):
            break
    return collected


def _find(msgs: list[dict], command: str, **fields) -> Optional[dict]:
    for m in msgs:
        if m.get("command") == command and all(m.get(k) == v for k, v in fields.items()):
            return m
    return None


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def _announce_client(port: int) -> DiscoveryClient:
    conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", port), spawn_if_missing=False)
    resp = _send_and_expect(conn, {"command": "announce", "type": "client"})
    assert "server_api_version" in resp
    return conn


def _announce_scanner(
    port: int,
    name: str = "test.v1",
    interfaces: list[str] | None = None,
    parameters: dict | None = None,
) -> DiscoveryClient:
    conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", port), spawn_if_missing=False)
    _send_and_expect(conn, {
        "command": "announce",
        "type": "scanner",
        "name": name,
        "interfaces": interfaces if interfaces is not None else ["eth0", "wlan0"],
        "parameters": parameters if parameters is not None else {"rate": 1.0},
    })
    return conn


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(port: int, persistent: bool = True):
    """Start a DiscoveryServer on the given port in a daemon thread. Returns (server, thread)."""
    server = DiscoveryServer()
    thread = threading.Thread(
        target=server.start,
        kwargs={"tcp_socket": ("127.0.0.1", port), "persistent": persistent},
        daemon=True,
    )
    thread.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    return server, thread


@pytest.fixture
def server_port(free_port):
    """Persistent DiscoveryServer on a random port. Yields the port."""
    _overflow.clear()
    server, thread = _start_server(free_port, persistent=True)
    yield free_port
    server.stop()
    thread.join(timeout=5.0)


@pytest.fixture
def client(server_port) -> DiscoveryClient:
    """Client connection that has completed the announce handshake."""
    conn = _announce_client(server_port)
    yield conn
    conn.close()


@pytest.fixture
def scanner(server_port, client) -> DiscoveryClient:
    """Scanner connection that has announced as 'test.v1'. Drains the fanout from client."""
    _drain(client)
    conn = _announce_scanner(server_port)
    _wait_for(client, "available_scanners_changed")
    _drain(client)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# TestSpawnIfMissing
# ---------------------------------------------------------------------------

class TestSpawnIfMissing:
    def test_false_raises_when_no_server(self, free_port):
        with pytest.raises((ConnectionRefusedError, FileNotFoundError)):
            DiscoveryClient.connect(tcp_socket=("127.0.0.1", free_port), spawn_if_missing=False)

    def test_true_spawns_server_and_connects(self, free_port):
        conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", free_port), spawn_if_missing=True)
        try:
            resp = _send_and_expect(conn, {"command": "announce", "type": "client"})
            assert resp.get("server_api_version") is not None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# TestServerLifecycle
# ---------------------------------------------------------------------------

class TestServerLifecycle:
    def test_persistent_survives_client_disconnect(self, free_port):
        server, thread = _start_server(free_port, persistent=True)
        try:
            conn = _announce_client(free_port)
            conn.close()
            time.sleep(0.6)  # past the server's select() timeout
            conn2 = _announce_client(free_port)
            conn2.close()
        finally:
            server.stop()
            thread.join(timeout=5.0)

    def test_non_persistent_exits_after_last_client(self, free_port):
        _server, thread = _start_server(free_port, persistent=False)
        conn = _announce_client(free_port)
        conn.close()
        thread.join(timeout=3.0)
        assert not thread.is_alive(), "Server should have stopped after last client disconnected"
        with pytest.raises((ConnectionRefusedError, OSError)):
            socket.create_connection(("127.0.0.1", free_port), timeout=0.5)


# ---------------------------------------------------------------------------
# TestAnnounce
# ---------------------------------------------------------------------------

class TestAnnounce:
    def test_client_announce_returns_api_version(self, server_port):
        conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", server_port), spawn_if_missing=False)
        resp = _send_and_expect(conn, {"command": "announce", "type": "client"})
        assert "server_api_version" in resp
        conn.close()

    def test_client_announce_includes_existing_scanners(self, server_port):
        scanner_conn = _announce_scanner(server_port, name="pre.v1")
        # Connect a second client — it should be able to see pre.v1 is registered.
        client_conn = _announce_client(server_port)
        resp = _send_and_expect(client_conn, {"command": "get_registered_scanners"})
        names = [s["name"] for s in resp.get("scanners", [])]
        assert "pre.v1" in names
        scanner_conn.close()
        client_conn.close()

    def test_scanner_announce_accepted(self, server_port):
        conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", server_port), spawn_if_missing=False)
        resp = _send_and_expect(conn, {
            "command": "announce",
            "type": "scanner",
            "name": "my.scanner",
            "interfaces": [],
            "parameters": {},
        })
        assert resp.get("status") == "accepted"
        conn.close()

    def test_scanner_announce_broadcasts_to_clients(self, client, server_port):
        _drain(client)
        scanner_conn = _announce_scanner(server_port, name="new.v1")
        msgs = _wait_for(client, "available_scanners_changed")
        msg = _find(msgs, "available_scanners_changed")
        assert msg is not None
        assert "new.v1" in msg.get("scanners", [])
        scanner_conn.close()

    def test_duplicate_scanner_announce_rejected(self, scanner, server_port):
        conn = DiscoveryClient.connect(tcp_socket=("127.0.0.1", server_port), spawn_if_missing=False)
        resp = _send_and_expect(conn, {
            "command": "announce",
            "type": "scanner",
            "name": "test.v1",
            "interfaces": [],
            "parameters": {},
        }, expected_status="rejected")
        assert "already registered" in resp.get("reason", "").lower()
        conn.close()


# ---------------------------------------------------------------------------
# TestClientCommands
# ---------------------------------------------------------------------------

class TestClientCommands:
    def test_get_builtin_scanners(self, client):
        resp = _send_and_expect(client, {"command": "get_builtin_scanners"})
        assert "test" in resp.get("scanners", [])
        assert "mdns.v1" in resp.get("scanners", [])

    def test_get_registered_scanners_empty(self, client):
        resp = _send_and_expect(client, {"command": "get_registered_scanners"})
        assert resp.get("scanners") == []

    def test_get_registered_scanners_with_scanner(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_registered_scanners"})
        names = [s["name"] for s in resp.get("scanners", [])]
        assert "test.v1" in names

    def test_get_registered_scanner_fields(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_registered_scanner", "scanner": "test.v1"})
        assert resp.get("name") == "test.v1"
        assert "available_interfaces" in resp
        assert "active_interfaces" in resp
        assert "parameters" in resp

    def test_get_registered_scanner_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "get_registered_scanner", "scanner": "nope"}, expected_status="rejected")

    def test_get_scanner_available_interfaces(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_scanner_available_interfaces", "scanner": "test.v1"})
        assert set(resp["interfaces"]) == {"eth0", "wlan0"}

    def test_get_scanner_available_interfaces_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "get_scanner_available_interfaces", "scanner": "nope"}, expected_status="rejected")

    def test_get_scanner_active_interfaces_empty_initially(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_scanner_active_interfaces", "scanner": "test.v1"})
        assert resp["interfaces"] == []

    def test_get_scanner_active_interfaces_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "get_scanner_active_interfaces", "scanner": "nope"}, expected_status="rejected")

    def test_get_scanner_parameters(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_scanner_parameters", "scanner": "test.v1"})
        assert resp.get("parameters") == {"rate": 1.0}

    def test_get_scanner_parameters_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "get_scanner_parameters", "scanner": "nope"}, expected_status="rejected")

    def test_set_active_interfaces_accepted_and_forwarded(self, client, scanner):
        _send_and_expect(client, {"command": "set_active_interfaces", "scanner": "test.v1", "interfaces": ["eth0"]})
        # Scanner should receive the forwarded command
        msg = _recv_one(scanner)
        assert msg.get("command") == "set_active_interfaces"
        assert msg.get("interfaces") == ["eth0"]

    def test_set_active_interfaces_unknown_interface_rejected(self, client, scanner):
        _send_and_expect(
            client,
            {"command": "set_active_interfaces", "scanner": "test.v1", "interfaces": ["tun99"]},
            expected_status="rejected",
        )

    def test_set_active_interfaces_unknown_scanner_rejected(self, client):
        _send_and_expect(client, {"command": "set_active_interfaces", "scanner": "nope", "interfaces": []}, expected_status="rejected")

    def test_set_scanner_parameters_accepted_and_forwarded(self, client, scanner):
        _send_and_expect(client, {
            "command": "set_scanner_parameters",
            "scanner": "test.v1",
            "parameters": [{"name": "rate", "value": 2.0}],
        })
        msg = _recv_one(scanner)
        assert msg.get("command") == "set_scanner_parameters"
        assert {"name": "rate", "value": 2.0} in msg.get("parameters", [])

    def test_set_scanner_parameters_unknown_param_rejected(self, client, scanner):
        _send_and_expect(client, {
            "command": "set_scanner_parameters",
            "scanner": "test.v1",
            "parameters": [{"name": "nosuchparam", "value": 1}],
        }, expected_status="rejected")

    def test_set_scanner_parameters_unknown_scanner_rejected(self, client):
        _send_and_expect(client, {"command": "set_scanner_parameters", "scanner": "nope", "parameters": []}, expected_status="rejected")

    def test_stop_scanner_accepted_and_forwarded(self, client, scanner):
        _send_and_expect(client, {"command": "stop_scanner", "scanner": "test.v1"})
        msg = _recv_one(scanner)
        assert msg.get("command") == "stop_scanner"

    def test_stop_scanner_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "stop_scanner", "scanner": "nope"}, expected_status="rejected")

    def test_clear_cache_accepted_and_forwarded(self, client, scanner):
        _send_and_expect(client, {"command": "clear_cache", "scanners": ["test.v1"]})
        msg = _recv_one(scanner)
        assert msg.get("command") == "clear_cache"

    def test_clear_cache_with_results_broadcasts_remove(self, client, scanner):
        scanner.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/host.local.", "result": {"x": 1}}],
        })
        _wait_for(client, "scan_results_update", scanner="test.v1")
        _drain(client)
        _send_and_expect(client, {"command": "clear_cache", "scanners": ["test.v1"]})
        msgs = _wait_for(client, "scan_results_remove", scanner="test.v1")
        msg = _find(msgs, "scan_results_remove", scanner="test.v1")
        assert msg is not None
        assert "eth0/host.local." in msg.get("keys", [])

    def test_clear_cache_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "clear_cache", "scanners": ["nope"]}, expected_status="rejected")

    def test_get_results_empty(self, client, scanner):
        resp = _send_and_expect(client, {"command": "get_results", "scanner": "test.v1"})
        assert resp.get("results") == []

    def test_get_results_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "get_results", "scanner": "nope"}, expected_status="rejected")

    def test_get_result_unknown_key_rejected(self, client, scanner):
        _send_and_expect(client, {"command": "get_result", "scanner": "test.v1", "key": "missing"}, expected_status="rejected")

    def test_get_result_unknown_scanner_rejected(self, client):
        _send_and_expect(client, {"command": "get_result", "scanner": "nope", "key": "k"}, expected_status="rejected")

    def test_start_builtin_scanner_unknown_rejected(self, client):
        _send_and_expect(client, {"command": "start_builtin_scanner", "scanner": "does.not.exist"}, expected_status="rejected")

    def test_unknown_command_does_not_crash_server(self, client):
        # Server rejects unknown commands and subsequent valid commands still work.
        _send_and_expect(client, {"command": "totally_unknown_xyz"}, expected_status="rejected")
        resp = _send_and_expect(client, {"command": "get_builtin_scanners"})
        assert "scanners" in resp


# ---------------------------------------------------------------------------
# TestScannerMessages
# ---------------------------------------------------------------------------

class TestScannerMessages:
    def test_available_interfaces_changed_updates_cache_and_broadcasts(self, client, scanner):
        scanner.send_msg({"command": "available_interfaces_changed", "interfaces": ["eth0", "eth1"]})
        msgs = _wait_for(client, "available_interfaces_changed", scanner="test.v1")
        msg = _find(msgs, "available_interfaces_changed", scanner="test.v1")
        assert msg is not None
        assert set(msg["interfaces"]) == {"eth0", "eth1"}
        resp = _send_and_expect(client, {"command": "get_scanner_available_interfaces", "scanner": "test.v1"})
        assert set(resp["interfaces"]) == {"eth0", "eth1"}

    def test_active_interfaces_changed_updates_cache_and_broadcasts(self, client, scanner):
        scanner.send_msg({"command": "active_interfaces_changed", "interfaces": ["eth0"]})
        msgs = _wait_for(client, "active_interfaces_changed", scanner="test.v1")
        msg = _find(msgs, "active_interfaces_changed", scanner="test.v1")
        assert msg is not None
        assert msg["interfaces"] == ["eth0"]
        resp = _send_and_expect(client, {"command": "get_scanner_active_interfaces", "scanner": "test.v1"})
        assert resp["interfaces"] == ["eth0"]

    def test_parameters_changed_updates_cache_and_broadcasts(self, client, scanner):
        scanner.send_msg({"command": "parameters_changed", "parameters": [{"name": "rate", "value": 5.0}]})
        msgs = _wait_for(client, "parameters_changed", scanner="test.v1")
        msg = _find(msgs, "parameters_changed", scanner="test.v1")
        assert msg is not None
        assert {"name": "rate", "value": 5.0} in msg["parameters"]
        resp = _send_and_expect(client, {"command": "get_scanner_parameters", "scanner": "test.v1"})
        assert resp["parameters"]["rate"] == 5.0

    def test_scan_results_update_stores_and_broadcasts(self, client, scanner):
        scanner.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/host.local.", "result": {"hostname": "host.local.", "addresses": ["1.2.3.4"]}}],
        })
        msgs = _wait_for(client, "scan_results_update", scanner="test.v1")
        msg = _find(msgs, "scan_results_update", scanner="test.v1")
        assert msg is not None
        assert any(r["key"] == "eth0/host.local." for r in msg["results"])
        resp = _send_and_expect(client, {"command": "get_results", "scanner": "test.v1"})
        assert any(r["key"] == "eth0/host.local." for r in resp["results"])

    def test_scan_results_update_gettable_by_key(self, client, scanner):
        scanner.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/device.local.", "result": {"x": 42}}],
        })
        _wait_for(client, "scan_results_update", scanner="test.v1")
        resp = _send_and_expect(client, {"command": "get_result", "scanner": "test.v1", "key": "eth0/device.local."})
        assert resp["result"] == {"x": 42}

    def test_scan_results_remove_deletes_and_broadcasts(self, client, scanner):
        scanner.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/gone.local.", "result": {"y": 2}}],
        })
        _wait_for(client, "scan_results_update", scanner="test.v1")
        _drain(client)
        scanner.send_msg({"command": "scan_results_remove", "keys": ["eth0/gone.local."]})
        msgs = _wait_for(client, "scan_results_remove", scanner="test.v1")
        msg = _find(msgs, "scan_results_remove", scanner="test.v1")
        assert msg is not None
        assert "eth0/gone.local." in msg["keys"]
        resp = _send_and_expect(client, {"command": "get_results", "scanner": "test.v1"})
        assert not any(r["key"] == "eth0/gone.local." for r in resp["results"])

    def test_scan_results_remove_unknown_keys_not_broadcast(self, client, scanner):
        scanner.send_msg({"command": "scan_results_remove", "keys": ["eth0/never.existed."]})
        msgs = _wait_for(client, "scan_results_remove", scanner="test.v1")
        msg = _find(msgs, "scan_results_remove", scanner="test.v1")
        # Unknown keys are filtered; the broadcast keys list should be empty.
        assert msg is not None
        assert msg["keys"] == []


# ---------------------------------------------------------------------------
# TestFanout
# ---------------------------------------------------------------------------

class TestFanout:
    def test_results_broadcast_to_multiple_clients(self, server_port, scanner):
        client2 = _announce_client(server_port)
        _drain(client2)
        try:
            scanner.send_msg({
                "command": "scan_results_update",
                "results": [{"key": "eth0/multi.local.", "result": {"z": 3}}],
            })
            msgs = _wait_for(client2, "scan_results_update", scanner="test.v1")
            assert _find(msgs, "scan_results_update", scanner="test.v1") is not None
        finally:
            client2.close()

    def test_scanner_disconnect_broadcasts_available_scanners_changed(self, client, server_port):
        scanner_conn = _announce_scanner(server_port, name="temp.v1")
        _wait_for(client, "available_scanners_changed")
        _drain(client)
        scanner_conn.close()
        msgs = _wait_for(client, "available_scanners_changed")
        msg = _find(msgs, "available_scanners_changed")
        assert msg is not None
        assert "temp.v1" not in msg.get("scanners", [])

    def test_scanner_disconnect_broadcasts_results_remove_for_cached_results(self, client, server_port):
        scanner_conn = _announce_scanner(server_port, name="temp.v1")
        _wait_for(client, "available_scanners_changed")
        _drain(client)
        scanner_conn.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/host.local.", "result": {"x": 1}}],
        })
        _wait_for(client, "scan_results_update", scanner="temp.v1")
        _drain(client)
        scanner_conn.close()
        msgs = _wait_for(client, "scan_results_remove", scanner="temp.v1")
        msg = _find(msgs, "scan_results_remove", scanner="temp.v1")
        assert msg is not None
        assert "eth0/host.local." in msg.get("keys", [])

    def test_scanner_disconnect_results_remove_before_available_scanners_changed(self, client, server_port):
        scanner_conn = _announce_scanner(server_port, name="temp.v1")
        _wait_for(client, "available_scanners_changed")
        _drain(client)
        scanner_conn.send_msg({
            "command": "scan_results_update",
            "results": [{"key": "eth0/host.local.", "result": {"x": 1}}],
        })
        _wait_for(client, "scan_results_update", scanner="temp.v1")
        _drain(client)
        scanner_conn.close()
        msgs = _wait_for(client, "available_scanners_changed")
        remove_idx = next((i for i, m in enumerate(msgs) if m.get("command") == "scan_results_remove" and m.get("scanner") == "temp.v1"), None)
        changed_idx = next((i for i, m in enumerate(msgs) if m.get("command") == "available_scanners_changed"), None)
        assert remove_idx is not None, "Expected scan_results_remove broadcast"
        assert changed_idx is not None, "Expected available_scanners_changed broadcast"
        assert remove_idx < changed_idx, "scan_results_remove must arrive before available_scanners_changed"
