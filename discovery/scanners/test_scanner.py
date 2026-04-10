"""
Test scanner for exercising the discovery server protocol.

Announces itself with a fixed set of fake interfaces so tests are hermetic and
independent of the host machine's actual network interfaces. The scanner's
behaviour is driven entirely through parameter changes sent by the test client,
allowing a test driver to put it into known states and observe the resulting
server fan-out messages.
"""

import argparse
import logging
import signal
import sys
import time
import uuid
from select import select

from pydantic import BaseModel

from discovery.scanners.base_scanner import BaseScanner
from discovery.scanners.mdns import MDNSHostData, MDNSServiceData


class ScannerResult(BaseModel):
    name: str
    value: str
    tags: list[str] = []


def _send(sock, msg: dict) -> None:
    sock.send_msg(msg)


def _recv_one(sock, timeout: float = 5.0) -> dict:
    ready, _, _ = select([sock], [], [], timeout)
    if not ready:
        raise RuntimeError(f"Timed out after {timeout}s waiting for a message")
    msgs = sock.read_msgs()
    if not msgs:
        raise RuntimeError("Connection closed before a message was received")
    return msgs[0]


logger = logging.getLogger("TestScanner")

# Fake hosts preserved for future discovery reporting tests.
_FAKE_HOSTS = [
    MDNSHostData.model_validate(
        {
            "hostname": "router.local.",
            "addresses": ["192.168.1.1", "fd00::1"],
            "interface": "eth0",
            "services": [
                {
                    "instance_name": "router HTTP",
                    "service_type": "_http._tcp",
                    "port": 80,
                    "txt": {},
                },
            ],
        }
    ),
    MDNSHostData.model_validate(
        {
            "hostname": "printer.local.",
            "addresses": ["192.168.1.50"],
            "interface": "eth0",
            "services": [
                {
                    "instance_name": "Office Printer",
                    "service_type": "_ipp._tcp",
                    "port": 631,
                    "txt": {"ty": "LaserJet"},
                },
            ],
        }
    ),
    MDNSHostData.model_validate(
        {
            "hostname": "nas.local.",
            "interface": "eth0",
            "addresses": ["192.168.1.10"],
            "services": [
                {
                    "instance_name": "NAS SMB",
                    "service_type": "_smb._tcp",
                    "port": 445,
                    "txt": {},
                },
                {
                    "instance_name": "NAS HTTP",
                    "service_type": "_http._tcp",
                    "port": 8080,
                    "txt": {"path": "/ui"},
                },
            ],
        }
    ),
]


class TestScanner(BaseScanner):
    def start(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(description="Test scanner")
        parser.add_argument(
            "--interval",
            type=float,
            default=2.0,
            help="select() timeout in seconds between heartbeat ticks",
        )
        parser.add_argument(
            "--available-interfaces",
            default="eth0,wlan0",
            help="Comma-separated fake interface list to report as available",
        )
        parser.add_argument(
            "--active-interfaces",
            default="",
            help="Comma-separated interfaces to report as initially active",
        )
        parser.add_argument(
            "--no-emit-available-on-start",
            dest="emit_available_on_start",
            action="store_false",
            default=True,
            help="Suppress the available_interfaces_changed sent after announce",
        )
        parser.add_argument(
            "--stop-delay",
            type=float,
            default=0.0,
            help="Seconds to wait before exiting after receiving stop_scanner",
        )
        parsed = parser.parse_args(args)

        try:
            self.connect_to_server()
        except Exception as e:
            logger.error("Unable to connect to discovery server", exc_info=e)
            raise

        assert self.server

        available = [i for i in parsed.available_interfaces.split(",") if i]
        active = [i for i in parsed.active_interfaces.split(",") if i]
        cache_clear_count = 0

        fake_results: dict[str, ScannerResult] = {
            str(uuid.uuid4()): ScannerResult(name="device-alpha", value="192.168.1.100", tags=["printer"]),
            str(uuid.uuid4()): ScannerResult(name="device-beta", value="192.168.1.101", tags=["nas", "storage"]),
            str(uuid.uuid4()): ScannerResult(name="device-gamma", value="192.168.1.102", tags=[]),
        }

        initial_parameters = {
            "interval": parsed.interval,
            "available_interfaces": parsed.available_interfaces,
            "active_interfaces": parsed.active_interfaces,
            "emit_available_on_start": parsed.emit_available_on_start,
            "stop_delay": parsed.stop_delay,
            "cache_clear_count": cache_clear_count,
        }

        _send(
            self.server,
            {
                "command": "announce",
                "type": "scanner",
                "name": "test",
                "interfaces": available,
                "parameters": initial_parameters,
            },
        )
        self.wait_for_registration()

        if parsed.emit_available_on_start:
            _send(
                self.server,
                {"command": "available_interfaces_changed", "interfaces": available},
            )
            _recv_one(self.server)

        _send(self.server, {
            "command": "scan_results_update",
            "results": [{"key": k, "result": v.model_dump()} for k, v in fake_results.items()],
        })
        _recv_one(self.server)

        self._continue_running = True

        while self._continue_running:
            ready, _, _ = select([self.server], [], [], parsed.interval)
            if not ready:
                # Heartbeat tick — reserved for future use.
                continue

            try:
                msgs = self.server.read_msgs()
            except ConnectionError:
                logger.info("Server connection closed, shutting down")
                break
            for msg in msgs:

                command = msg.get("command")

                match command:
                    case "set_scanner_parameters":
                        changed_params = []
                        emit_available = False
                        emit_active = False

                        for entry in msg.get("parameters", []):
                            name = entry.get("name")
                            value = entry.get("value")
                            initial_parameters[name] = value
                            changed_params.append(entry)

                            if name == "available_interfaces":
                                available = [i for i in value.split(",") if i]
                                emit_available = True
                            elif name == "active_interfaces":
                                active = [i for i in value.split(",") if i]
                                emit_active = True
                            elif name == "interval":
                                parsed.interval = float(value)
                            elif name == "stop_delay":
                                parsed.stop_delay = float(value)

                        if emit_available:
                            _send(
                                self.server,
                                {
                                    "command": "available_interfaces_changed",
                                    "interfaces": available,
                                },
                            )
                            _recv_one(self.server)

                        if emit_active:
                            _send(
                                self.server,
                                {
                                    "command": "active_interfaces_changed",
                                    "interfaces": active,
                                },
                            )
                            _recv_one(self.server)

                        _send(
                            self.server,
                            {
                                "command": "parameters_changed",
                                "parameters": changed_params,
                            },
                        )
                        _recv_one(self.server)

                    case "set_active_interfaces":
                        active = msg.get("interfaces", [])
                        initial_parameters["active_interfaces"] = ",".join(active)
                        _send(
                            self.server,
                            {
                                "command": "active_interfaces_changed",
                                "interfaces": active,
                            },
                        )
                        _recv_one(self.server)

                    case "clear_cache":
                        cache_clear_count += 1
                        initial_parameters["cache_clear_count"] = cache_clear_count
                        _send(
                            self.server,
                            {
                                "command": "parameters_changed",
                                "parameters": [
                                    {
                                        "name": "cache_clear_count",
                                        "value": cache_clear_count,
                                    }
                                ],
                            },
                        )
                        _recv_one(self.server)
                        _send(self.server, {
                            "command": "scan_results_update",
                            "results": [{"key": k, "result": v.model_dump()} for k, v in fake_results.items()],
                        })
                        _recv_one(self.server)

                    case "stop_scanner":
                        if parsed.stop_delay > 0:
                            time.sleep(parsed.stop_delay)
                        self._continue_running = False
                        break

                    case unknown:
                        logger.warning(f"Unknown command from server: {unknown!r}")

    def stop(self) -> None:
        self._continue_running = False


if __name__ == "__main__":
    scanner = TestScanner()
    extra_args = scanner.parse_connection_args(sys.argv[1:])

    def _handle_sigint(signum, frame):
        scanner.stop()

    signal.signal(signal.SIGINT, _handle_sigint)
    scanner.start(extra_args)
