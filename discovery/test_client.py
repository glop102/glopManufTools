"""
Test driver for the discovery protocol.

Connects as a client and exercises the full client->server message set, verifying
responses and fan-out messages at each step. The TestScanner is the instrument
being controlled — it is started via start_builtin_scanner and put into various
states through parameter commands routed through the server.

Usage:
    python -m discovery.test_client --unix-socket /tmp/discovery_test
    python -m discovery.test_client --tcp-socket 127.0.0.1:9999
"""

import argparse
import json
import sys
import time
from collections import deque
from pathlib import Path
from select import select
from typing import Optional

from discovery.client import DiscoveryClient

# read_msgs() greedily drains the socket buffer and may return multiple messages
# in one call. _recv_one only needs one, so extras are parked here for _drain.
_overflow: deque[dict] = deque()


def _send(sock, msg: dict) -> None:
    sock.send_msg(json.dumps(msg))


def _recv_one(sock, timeout: float = 5.0) -> dict:
    if _overflow:
        return _overflow.popleft()
    ready, _, _ = select([sock], [], [], timeout)
    if not ready:
        raise RuntimeError(f"Timed out after {timeout}s waiting for a message")
    msgs = sock.read_msgs()
    if not msgs:
        raise RuntimeError("Connection closed before a message was received")
    _overflow.extend(json.loads(m) for m in msgs[1:])
    return json.loads(msgs[0])


def _send_and_expect(
    sock, msg: dict, expected_status: str = "accepted", timeout: float = 5.0
) -> dict:
    _send(sock, msg)
    response = _recv_one(sock, timeout=timeout)
    if response.get("status") != expected_status:
        raise AssertionError(
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
        for raw in sock.read_msgs():
            collected.append(json.loads(raw))
    return collected


from discovery._utils import _parse_tcp_socket


_passed = 0
_failed = 0


def _check(label: str, condition: bool, detail: str = "") -> bool:
    global _passed, _failed
    if condition:
        print(f"  PASS  {label}")
        _passed += 1
        return True
    else:
        print(f"  FAIL  {label}{': ' + detail if detail else ''}")
        _failed += 1
        return False


def _find_in_drain(msgs: list[dict], command: str, **fields) -> Optional[dict]:
    """Return the first message in msgs matching command and all provided fields."""
    for msg in msgs:
        if msg.get("command") != command:
            continue
        if all(msg.get(k) == v for k, v in fields.items()):
            return msg
    return None


def run_tests(
    unix_socket_path: Optional[Path],
    tcp_socket: Optional[tuple[str, int]],
) -> int:

    raw_conn = DiscoveryClient.connect(
        unix_socket_path=unix_socket_path,
        tcp_socket=tcp_socket,
        spawn_if_missing=True,
    )

    print("\n-- T1: announce as client --")
    resp = _send_and_expect(raw_conn, {"command": "announce", "type": "client"})
    _check("server_api_version present", "server_api_version" in resp, str(resp))
    _check("scanners field present", "scanners" in resp, str(resp))

    print("\n-- T2: get_builtin_scanners --")
    resp = _send_and_expect(raw_conn, {"command": "get_builtin_scanners"})
    _check('"test" in builtin scanners', "test" in resp.get("scanners", []), str(resp))

    print('\n-- T3: start_builtin_scanner "test" --')
    _send_and_expect(raw_conn, {"command": "start_builtin_scanner", "scanner": "test"})
    # Wait for the scanner subprocess to connect and announce itself.
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += _drain(raw_conn, timeout=0.3)
        if _find_in_drain(fanout, "available_scanners_changed") and _find_in_drain(
            fanout, "available_interfaces_changed", scanner="test"
        ):
            break
    _check(
        "available_scanners_changed received with 'test'",
        any(
            "test" in m.get("scanners", [])
            for m in fanout
            if m.get("command") == "available_scanners_changed"
        ),
        str(fanout),
    )
    _check(
        "available_interfaces_changed received for 'test'",
        _find_in_drain(fanout, "available_interfaces_changed", scanner="test")
        is not None,
        str(fanout),
    )

    print("\n-- T4: start_builtin_scanner unknown --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "start_builtin_scanner", "scanner": "does_not_exist"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print("\n-- T5: get_registered_scanners --")
    resp = _send_and_expect(raw_conn, {"command": "get_registered_scanners"})
    scanners = resp.get("scanners", [])
    _check(
        "test scanner listed", any(s.get("name") == "test" for s in scanners), str(resp)
    )

    print('\n-- T6: get_registered_scanner "test" --')
    resp = _send_and_expect(
        raw_conn, {"command": "get_registered_scanner", "scanner": "test"}
    )
    for field in ("name", "available_interfaces", "active_interfaces", "parameters"):
        _check(f"{field} field present", field in resp, str(resp))

    print("\n-- T7: get_registered_scanner unknown --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "get_registered_scanner", "scanner": "no_such_scanner"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print("\n-- T8: get_scanner_available_interfaces --")
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_available_interfaces", "scanner": "test"}
    )
    interfaces = resp.get("interfaces", [])
    _check("eth0 in available interfaces", "eth0" in interfaces, str(resp))
    _check("wlan0 in available interfaces", "wlan0" in interfaces, str(resp))

    print("\n-- T9: get_scanner_active_interfaces --")
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_active_interfaces", "scanner": "test"}
    )
    _check("active interfaces empty at start", resp.get("interfaces") == [], str(resp))

    print("\n-- T10: get_scanner_parameters --")
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_parameters", "scanner": "test"}
    )
    params = resp.get("parameters", {})
    for key in (
        "interval",
        "available_interfaces",
        "active_interfaces",
        "cache_clear_count",
    ):
        _check(f"parameter {key!r} present", key in params, str(params))

    print("\n-- T11: set_scanner_parameters (change available_interfaces) --")
    _send_and_expect(
        raw_conn,
        {
            "command": "set_scanner_parameters",
            "scanner": "test",
            "parameters": [
                {"name": "available_interfaces", "value": "eth0,wlan0,eth1"}
            ],
        },
    )
    fanout = _drain(raw_conn, timeout=1.0)
    avail_msg = _find_in_drain(fanout, "available_interfaces_changed", scanner="test")
    _check(
        "available_interfaces_changed fan-out received",
        avail_msg is not None,
        str(fanout),
    )
    _check(
        "eth1 in new available interfaces",
        avail_msg is not None and "eth1" in avail_msg.get("interfaces", []),
        str(avail_msg),
    )
    _check(
        "parameters_changed fan-out received",
        _find_in_drain(fanout, "parameters_changed", scanner="test") is not None,
        str(fanout),
    )
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_available_interfaces", "scanner": "test"}
    )
    _check("server cached eth1", "eth1" in resp.get("interfaces", []), str(resp))

    print("\n-- T12: set_scanner_parameters (unknown parameter) --")
    resp = _send_and_expect(
        raw_conn,
        {
            "command": "set_scanner_parameters",
            "scanner": "test",
            "parameters": [{"name": "does_not_exist", "value": "x"}],
        },
        expected_status="rejected",
    )
    _check("parameters field in rejection", "parameters" in resp, str(resp))
    _check(
        "unknown name listed in rejection",
        "does_not_exist" in resp.get("parameters", []),
        str(resp),
    )

    print("\n-- T13: set_active_interfaces (valid) --")
    _send_and_expect(
        raw_conn,
        {
            "command": "set_active_interfaces",
            "scanner": "test",
            "interfaces": ["eth0"],
        },
    )
    fanout = _drain(raw_conn, timeout=1.0)
    active_msg = _find_in_drain(fanout, "active_interfaces_changed", scanner="test")
    _check(
        "active_interfaces_changed fan-out received",
        active_msg is not None,
        str(fanout),
    )
    _check(
        "eth0 in active interfaces",
        active_msg is not None and "eth0" in active_msg.get("interfaces", []),
        str(active_msg),
    )
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_active_interfaces", "scanner": "test"}
    )
    _check(
        "server cached active interface",
        "eth0" in resp.get("interfaces", []),
        str(resp),
    )

    print("\n-- T14: set_active_interfaces (invalid interface) --")
    resp = _send_and_expect(
        raw_conn,
        {
            "command": "set_active_interfaces",
            "scanner": "test",
            "interfaces": ["fake99"],
        },
        expected_status="rejected",
    )
    _check("interfaces field in rejection", "interfaces" in resp, str(resp))
    _check(
        "fake99 listed in rejection", "fake99" in resp.get("interfaces", []), str(resp)
    )

    print("\n-- T15: set_active_interfaces (scanner not found) --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "set_active_interfaces", "scanner": "no_such", "interfaces": []},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print("\n-- T16: clear_cache (valid) --")
    _send_and_expect(raw_conn, {"command": "clear_cache", "scanners": ["test"]})
    fanout = _drain(raw_conn, timeout=1.0)
    remove_msg = _find_in_drain(fanout, "scan_results_remove", scanner="test")
    _check("scan_results_remove fan-out received", remove_msg is not None, str(fanout))
    _check(
        "all three keys present in remove",
        remove_msg is not None and len(remove_msg.get("keys", [])) == 3,
        str(remove_msg),
    )
    update_msg = _find_in_drain(fanout, "scan_results_update", scanner="test")
    _check("scan_results_update fan-out received after repopulate", update_msg is not None, str(fanout))
    _check(
        "three results in repopulate update",
        update_msg is not None and len(update_msg.get("results", [])) == 3,
        str(update_msg),
    )
    params_msg = _find_in_drain(fanout, "parameters_changed", scanner="test")
    _check("parameters_changed fan-out received", params_msg is not None, str(fanout))
    cache_clear_entry = next(
        (
            p
            for p in (params_msg or {}).get("parameters", [])
            if p.get("name") == "cache_clear_count"
        ),
        None,
    )
    _check(
        "cache_clear_count in parameters_changed",
        cache_clear_entry is not None,
        str(params_msg),
    )
    _check(
        "cache_clear_count incremented to 1",
        cache_clear_entry is not None and cache_clear_entry.get("value") == 1,
        str(cache_clear_entry),
    )
    resp = _send_and_expect(
        raw_conn, {"command": "get_scanner_parameters", "scanner": "test"}
    )
    _check(
        "server cached cache_clear_count=1",
        resp.get("parameters", {}).get("cache_clear_count") == 1,
        str(resp),
    )

    print("\n-- T17: clear_cache (unknown scanner) --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "clear_cache", "scanners": ["phantom"]},
        expected_status="rejected",
    )
    _check("scanners field in rejection", "scanners" in resp, str(resp))
    _check(
        "phantom listed in rejection", "phantom" in resp.get("scanners", []), str(resp)
    )

    print("\n-- T18: stop_scanner (valid) --")
    _send_and_expect(raw_conn, {"command": "stop_scanner", "scanner": "test"})
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += _drain(raw_conn, timeout=0.3)
        if _find_in_drain(fanout, "available_scanners_changed"):
            break
    scanner_change = _find_in_drain(fanout, "available_scanners_changed")
    _check(
        "available_scanners_changed received", scanner_change is not None, str(fanout)
    )
    _check(
        "'test' absent from scanner list after stop",
        scanner_change is not None and "test" not in scanner_change.get("scanners", []),
        str(scanner_change),
    )

    print("\n-- T19: stop_scanner (scanner already gone) --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "stop_scanner", "scanner": "test"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print("\n-- T20: re-start scanner and verify clean registration --")
    _send_and_expect(raw_conn, {"command": "start_builtin_scanner", "scanner": "test"})
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += _drain(raw_conn, timeout=0.3)
        if any(
            "test" in m.get("scanners", [])
            for m in fanout
            if m.get("command") == "available_scanners_changed"
        ):
            break
    _check(
        "available_scanners_changed received with 'test' after re-start",
        any(
            "test" in m.get("scanners", [])
            for m in fanout
            if m.get("command") == "available_scanners_changed"
        ),
        str(fanout),
    )

    # Drain any remaining fan-out from T20 (available_interfaces_changed + scan_results_update)
    _drain(raw_conn, timeout=1.0)

    print("\n-- T21: get_results --")
    resp = _send_and_expect(raw_conn, {"command": "get_results", "scanner": "test"})
    results = resp.get("results", [])
    _check("three results in cache", len(results) == 3, str(results))
    _check("each result has key and result fields", all("key" in r and "result" in r for r in results), str(results))
    first_key = results[0]["key"] if results else None

    print("\n-- T22: get_result (valid key) --")
    if first_key:
        resp = _send_and_expect(raw_conn, {"command": "get_result", "scanner": "test", "key": first_key})
        _check("key field present", "key" in resp, str(resp))
        _check("result field present", "result" in resp, str(resp))
        _check("name field in result", "name" in resp.get("result", {}), str(resp))

    print("\n-- T23: get_result (unknown key) --")
    resp = _send_and_expect(
        raw_conn,
        {"command": "get_result", "scanner": "test", "key": "no-such-key"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print(f"\n{_passed} passed, {_failed} failed")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Discovery protocol test client")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unix-socket", type=Path, metavar="PATH")
    group.add_argument("--tcp-socket", type=_parse_tcp_socket, metavar="HOST:PORT")
    parsed_args = parser.parse_args()

    sys.exit(
        run_tests(
            unix_socket_path=parsed_args.unix_socket,
            tcp_socket=parsed_args.tcp_socket,
        )
    )
