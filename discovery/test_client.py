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
import sys
import time
from pathlib import Path
from typing import Optional

from discovery.client import DiscoveryClient
from discovery.protocol_client import ProtocolClient


def _parse_tcp_socket(value: str) -> tuple[str, int]:
    if value.startswith("["):
        bracket_end = value.index("]")
        host = value[1:bracket_end]
        port = int(value[bracket_end + 2:])
    else:
        host, _, port_str = value.rpartition(":")
        port = int(port_str)
    return host, port


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
    proto = ProtocolClient(raw_conn)

    print("\n-- T1: announce as client --")
    resp = proto.send_and_expect({"command": "announce", "type": "client"})
    _check("server_api_version present", "server_api_version" in resp, str(resp))
    _check("scanners field present", "scanners" in resp, str(resp))

    print("\n-- T2: get_builtin_scanners --")
    resp = proto.send_and_expect({"command": "get_builtin_scanners"})
    _check('"test" in builtin scanners', "test" in resp.get("scanners", []), str(resp))

    print('\n-- T3: start_builtin_scanner "test" --')
    proto.send_and_expect({"command": "start_builtin_scanner", "scanner": "test"})
    # Wait for the scanner subprocess to connect and announce itself.
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += proto.drain(timeout=0.3)
        if _find_in_drain(fanout, "available_scanners_changed") and \
           _find_in_drain(fanout, "available_interfaces_changed", scanner="test"):
            break
    _check(
        "available_scanners_changed received with 'test'",
        any(
            "test" in m.get("scanners", [])
            for m in fanout if m.get("command") == "available_scanners_changed"
        ),
        str(fanout),
    )
    _check(
        "available_interfaces_changed received for 'test'",
        _find_in_drain(fanout, "available_interfaces_changed", scanner="test") is not None,
        str(fanout),
    )

    print('\n-- T4: start_builtin_scanner unknown --')
    resp = proto.send_and_expect(
        {"command": "start_builtin_scanner", "scanner": "does_not_exist"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print("\n-- T5: get_registered_scanners --")
    resp = proto.send_and_expect({"command": "get_registered_scanners"})
    scanners = resp.get("scanners", [])
    _check("test scanner listed", any(s.get("name") == "test" for s in scanners), str(resp))

    print('\n-- T6: get_registered_scanner "test" --')
    resp = proto.send_and_expect({"command": "get_registered_scanner", "scanner": "test"})
    for field in ("name", "available_interfaces", "active_interfaces", "parameters"):
        _check(f"{field} field present", field in resp, str(resp))

    print('\n-- T7: get_registered_scanner unknown --')
    resp = proto.send_and_expect(
        {"command": "get_registered_scanner", "scanner": "no_such_scanner"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print('\n-- T8: get_scanner_available_interfaces --')
    resp = proto.send_and_expect({"command": "get_scanner_available_interfaces", "scanner": "test"})
    interfaces = resp.get("interfaces", [])
    _check("eth0 in available interfaces", "eth0" in interfaces, str(resp))
    _check("wlan0 in available interfaces", "wlan0" in interfaces, str(resp))

    print('\n-- T9: get_scanner_active_interfaces --')
    resp = proto.send_and_expect({"command": "get_scanner_active_interfaces", "scanner": "test"})
    _check("active interfaces empty at start", resp.get("interfaces") == [], str(resp))

    print('\n-- T10: get_scanner_parameters --')
    resp = proto.send_and_expect({"command": "get_scanner_parameters", "scanner": "test"})
    params = resp.get("parameters", {})
    for key in ("interval", "available_interfaces", "active_interfaces", "cache_clear_count"):
        _check(f"parameter {key!r} present", key in params, str(params))

    print('\n-- T11: set_scanner_parameters (change available_interfaces) --')
    proto.send_and_expect({
        "command": "set_scanner_parameters",
        "scanner": "test",
        "parameters": [{"name": "available_interfaces", "value": "eth0,wlan0,eth1"}],
    })
    fanout = proto.drain(timeout=1.0)
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
    resp = proto.send_and_expect({"command": "get_scanner_available_interfaces", "scanner": "test"})
    _check("server cached eth1", "eth1" in resp.get("interfaces", []), str(resp))

    print('\n-- T12: set_scanner_parameters (unknown parameter) --')
    resp = proto.send_and_expect(
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

    print('\n-- T13: set_active_interfaces (valid) --')
    proto.send_and_expect({
        "command": "set_active_interfaces",
        "scanner": "test",
        "interfaces": ["eth0"],
    })
    fanout = proto.drain(timeout=1.0)
    active_msg = _find_in_drain(fanout, "active_interfaces_changed", scanner="test")
    _check("active_interfaces_changed fan-out received", active_msg is not None, str(fanout))
    _check(
        "eth0 in active interfaces",
        active_msg is not None and "eth0" in active_msg.get("interfaces", []),
        str(active_msg),
    )
    resp = proto.send_and_expect({"command": "get_scanner_active_interfaces", "scanner": "test"})
    _check("server cached active interface", "eth0" in resp.get("interfaces", []), str(resp))

    print('\n-- T14: set_active_interfaces (invalid interface) --')
    resp = proto.send_and_expect(
        {"command": "set_active_interfaces", "scanner": "test", "interfaces": ["fake99"]},
        expected_status="rejected",
    )
    _check("interfaces field in rejection", "interfaces" in resp, str(resp))
    _check("fake99 listed in rejection", "fake99" in resp.get("interfaces", []), str(resp))

    print('\n-- T15: set_active_interfaces (scanner not found) --')
    resp = proto.send_and_expect(
        {"command": "set_active_interfaces", "scanner": "no_such", "interfaces": []},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print('\n-- T16: clear_cache (valid) --')
    proto.send_and_expect({"command": "clear_cache", "scanners": ["test"]})
    fanout = proto.drain(timeout=1.0)
    params_msg = _find_in_drain(fanout, "parameters_changed", scanner="test")
    _check("parameters_changed fan-out received", params_msg is not None, str(fanout))
    cache_clear_entry = next(
        (p for p in (params_msg or {}).get("parameters", []) if p.get("name") == "cache_clear_count"),
        None,
    )
    _check("cache_clear_count in parameters_changed", cache_clear_entry is not None, str(params_msg))
    _check("cache_clear_count incremented to 1", cache_clear_entry is not None and cache_clear_entry.get("value") == 1, str(cache_clear_entry))
    resp = proto.send_and_expect({"command": "get_scanner_parameters", "scanner": "test"})
    _check("server cached cache_clear_count=1", resp.get("parameters", {}).get("cache_clear_count") == 1, str(resp))

    print('\n-- T17: clear_cache (unknown scanner) --')
    resp = proto.send_and_expect(
        {"command": "clear_cache", "scanners": ["phantom"]},
        expected_status="rejected",
    )
    _check("scanners field in rejection", "scanners" in resp, str(resp))
    _check("phantom listed in rejection", "phantom" in resp.get("scanners", []), str(resp))

    print('\n-- T18: stop_scanner (valid) --')
    proto.send_and_expect({"command": "stop_scanner", "scanner": "test"})
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += proto.drain(timeout=0.3)
        if _find_in_drain(fanout, "available_scanners_changed"):
            break
    scanner_change = _find_in_drain(fanout, "available_scanners_changed")
    _check("available_scanners_changed received", scanner_change is not None, str(fanout))
    _check(
        "'test' absent from scanner list after stop",
        scanner_change is not None and "test" not in scanner_change.get("scanners", []),
        str(scanner_change),
    )

    print('\n-- T19: stop_scanner (scanner already gone) --')
    resp = proto.send_and_expect(
        {"command": "stop_scanner", "scanner": "test"},
        expected_status="rejected",
    )
    _check("reason field present", "reason" in resp, str(resp))

    print('\n-- T20: re-start scanner and verify clean registration --')
    proto.send_and_expect({"command": "start_builtin_scanner", "scanner": "test"})
    fanout = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        fanout += proto.drain(timeout=0.3)
        if any("test" in m.get("scanners", []) for m in fanout if m.get("command") == "available_scanners_changed"):
            break
    _check(
        "available_scanners_changed received with 'test' after re-start",
        any(
            "test" in m.get("scanners", [])
            for m in fanout if m.get("command") == "available_scanners_changed"
        ),
        str(fanout),
    )

    print(f"\n{_passed} passed, {_failed} failed")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Discovery protocol test client")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unix-socket", type=Path, metavar="PATH")
    group.add_argument("--tcp-socket", type=_parse_tcp_socket, metavar="HOST:PORT")
    parsed_args = parser.parse_args()

    sys.exit(run_tests(
        unix_socket_path=parsed_args.unix_socket,
        tcp_socket=parsed_args.tcp_socket,
    ))
