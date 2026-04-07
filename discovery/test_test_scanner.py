"""
Pytest tests for the discovery protocol, exercising the server via the TestScanner.

Each test gets a fresh server and client connection via the session-scoped fixtures.
The server is started on a random TCP port so tests don't interfere with a
running production server and don't require a unix socket path on disk.
"""

import socket
import time
from collections import deque
from select import select
from typing import Optional

import pytest

from discovery.client import DiscoveryClient


# ---------------------------------------------------------------------------
# Helpers (mirrors the bespoke helpers in test_client.py)
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
    """Drain until `command` (matching **fields) appears or deadline passes. Returns all collected messages."""
    collected: list[dict] = []
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        collected += _drain(sock, timeout=0.3)
        if _find(collected, command, **fields):
            break
    return collected


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def free_port() -> int:
    """Pick a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server_conn(free_port):
    """
    Spawn the discovery server on a random TCP port, connect as a client, and
    announce.  Shared for the whole module so the server and TestScanner state
    persist across tests (they are ordered and stateful by design).
    """
    _overflow.clear()
    conn = DiscoveryClient.connect(
        tcp_socket=("127.0.0.1", free_port),
        spawn_if_missing=True,
    )
    resp = _send_and_expect(conn, {"command": "announce", "type": "client"})
    assert "server_api_version" in resp
    assert "scanners" in resp
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAnnounce:
    def test_server_api_version_present(self, server_conn):
        # Re-use the already-announced connection; we just verify the announce
        # response fields were correct (checked during fixture setup).
        resp = _send_and_expect(server_conn, {"command": "get_builtin_scanners"})
        assert "scanners" in resp

    def test_test_scanner_in_builtins(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_builtin_scanners"})
        assert "test" in resp.get("scanners", [])


class TestStartScanner:
    def test_start_test_scanner(self, server_conn):
        _send_and_expect(server_conn, {"command": "start_builtin_scanner", "scanner": "test"})
        fanout = _wait_for(server_conn, "available_interfaces_changed", scanner="test")
        assert _find(fanout, "available_scanners_changed") is not None, \
            f"available_scanners_changed not received; got: {fanout}"
        assert _find(fanout, "available_interfaces_changed", scanner="test") is not None, \
            f"available_interfaces_changed for 'test' not received; got: {fanout}"
        assert any(
            "test" in m.get("scanners", [])
            for m in fanout
            if m.get("command") == "available_scanners_changed"
        )

    def test_start_unknown_scanner_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "start_builtin_scanner", "scanner": "does_not_exist"},
            expected_status="rejected",
        )
        assert "reason" in resp


class TestGetRegistered:
    def test_test_scanner_listed(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_registered_scanners"})
        scanners = resp.get("scanners", [])
        assert any(s.get("name") == "test" for s in scanners)

    def test_get_registered_scanner_fields(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_registered_scanner", "scanner": "test"})
        for field in ("name", "available_interfaces", "active_interfaces", "parameters"):
            assert field in resp, f"Missing field {field!r} in {resp}"

    def test_get_registered_scanner_unknown_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_registered_scanner", "scanner": "no_such_scanner"},
            expected_status="rejected",
        )
        assert "reason" in resp


class TestInterfaces:
    def test_available_interfaces_contains_eth0_wlan0(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_scanner_available_interfaces", "scanner": "test"},
        )
        ifaces = resp.get("interfaces", [])
        assert "eth0" in ifaces
        assert "wlan0" in ifaces

    def test_active_interfaces_empty_at_start(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_scanner_active_interfaces", "scanner": "test"},
        )
        assert resp.get("interfaces") == []


class TestParameters:
    def test_expected_parameters_present(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_scanner_parameters", "scanner": "test"})
        params = resp.get("parameters", {})
        for key in ("interval", "available_interfaces", "active_interfaces", "cache_clear_count"):
            assert key in params, f"Parameter {key!r} missing from {params}"

    def test_set_available_interfaces_fanout(self, server_conn):
        _send_and_expect(
            server_conn,
            {
                "command": "set_scanner_parameters",
                "scanner": "test",
                "parameters": [{"name": "available_interfaces", "value": "eth0,wlan0,eth1"}],
            },
        )
        fanout = _drain(server_conn, timeout=1.0)
        avail_msg = _find(fanout, "available_interfaces_changed", scanner="test")
        assert avail_msg is not None, f"available_interfaces_changed not in fanout: {fanout}"
        assert "eth1" in avail_msg.get("interfaces", [])
        assert _find(fanout, "parameters_changed", scanner="test") is not None

    def test_set_available_interfaces_server_cached(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_scanner_available_interfaces", "scanner": "test"},
        )
        assert "eth1" in resp.get("interfaces", [])

    def test_set_unknown_parameter_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {
                "command": "set_scanner_parameters",
                "scanner": "test",
                "parameters": [{"name": "does_not_exist", "value": "x"}],
            },
            expected_status="rejected",
        )
        assert "parameters" in resp
        assert "does_not_exist" in resp.get("parameters", [])


class TestSetActiveInterfaces:
    def test_set_active_interface_valid(self, server_conn):
        _send_and_expect(
            server_conn,
            {"command": "set_active_interfaces", "scanner": "test", "interfaces": ["eth0"]},
        )
        fanout = _drain(server_conn, timeout=1.0)
        active_msg = _find(fanout, "active_interfaces_changed", scanner="test")
        assert active_msg is not None, f"active_interfaces_changed not in fanout: {fanout}"
        assert "eth0" in active_msg.get("interfaces", [])

    def test_set_active_interface_server_cached(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_scanner_active_interfaces", "scanner": "test"},
        )
        assert "eth0" in resp.get("interfaces", [])

    def test_set_active_interface_invalid_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "set_active_interfaces", "scanner": "test", "interfaces": ["fake99"]},
            expected_status="rejected",
        )
        assert "interfaces" in resp
        assert "fake99" in resp.get("interfaces", [])

    def test_set_active_interface_unknown_scanner_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "set_active_interfaces", "scanner": "no_such", "interfaces": []},
            expected_status="rejected",
        )
        assert "reason" in resp


class TestClearCache:
    def test_clear_cache_valid(self, server_conn):
        _send_and_expect(server_conn, {"command": "clear_cache", "scanners": ["test"]})
        fanout = _drain(server_conn, timeout=1.0)

        remove_msg = _find(fanout, "scan_results_remove", scanner="test")
        assert remove_msg is not None, f"scan_results_remove not in fanout: {fanout}"
        assert len(remove_msg.get("keys", [])) == 3

        update_msg = _find(fanout, "scan_results_update", scanner="test")
        assert update_msg is not None, f"scan_results_update not in fanout: {fanout}"
        assert len(update_msg.get("results", [])) == 3

        params_msg = _find(fanout, "parameters_changed", scanner="test")
        assert params_msg is not None, f"parameters_changed not in fanout: {fanout}"
        cache_entry = next(
            (p for p in params_msg.get("parameters", []) if p.get("name") == "cache_clear_count"),
            None,
        )
        assert cache_entry is not None
        assert cache_entry.get("value") == 1

    def test_clear_cache_server_cached_count(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_scanner_parameters", "scanner": "test"})
        assert resp.get("parameters", {}).get("cache_clear_count") == 1

    def test_clear_cache_unknown_scanner_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "clear_cache", "scanners": ["phantom"]},
            expected_status="rejected",
        )
        assert "scanners" in resp
        assert "phantom" in resp.get("scanners", [])


class TestStopScanner:
    def test_stop_scanner_valid(self, server_conn):
        _send_and_expect(server_conn, {"command": "stop_scanner", "scanner": "test"})
        fanout = _wait_for(server_conn, "available_scanners_changed")
        scanner_change = _find(fanout, "available_scanners_changed")
        assert scanner_change is not None
        assert "test" not in scanner_change.get("scanners", [])

    def test_stop_scanner_already_gone_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "stop_scanner", "scanner": "test"},
            expected_status="rejected",
        )
        assert "reason" in resp


class TestRestartAndResults:
    def test_restart_scanner_clean_registration(self, server_conn):
        _send_and_expect(server_conn, {"command": "start_builtin_scanner", "scanner": "test"})
        fanout = _wait_for(server_conn, "available_scanners_changed", deadline_secs=5.0)
        assert any(
            "test" in m.get("scanners", [])
            for m in fanout
            if m.get("command") == "available_scanners_changed"
        ), f"available_scanners_changed with 'test' not received: {fanout}"
        # Drain residual fan-out (available_interfaces_changed + scan_results_update)
        _drain(server_conn, timeout=1.0)

    def test_get_results_returns_three(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_results", "scanner": "test"})
        results = resp.get("results", [])
        assert len(results) == 3
        assert all("key" in r and "result" in r for r in results)

    def test_get_result_valid_key(self, server_conn):
        resp = _send_and_expect(server_conn, {"command": "get_results", "scanner": "test"})
        first_key = resp["results"][0]["key"]
        resp2 = _send_and_expect(
            server_conn,
            {"command": "get_result", "scanner": "test", "key": first_key},
        )
        assert "key" in resp2
        assert "result" in resp2
        assert "name" in resp2.get("result", {})

    def test_get_result_unknown_key_rejected(self, server_conn):
        resp = _send_and_expect(
            server_conn,
            {"command": "get_result", "scanner": "test", "key": "no-such-key"},
            expected_status="rejected",
        )
        assert "reason" in resp
