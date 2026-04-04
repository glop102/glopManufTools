import argparse
import importlib
import json
import os
import signal
from select import select
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional, Self
import logging

from .msg_socket import MsgSocket
from ._utils import _parse_tcp_socket

logger = logging.getLogger("discovery")


class ScannerConnection(MsgSocket):
    """
    Server-side representation of a connected scanner process.
    Wraps the MsgSocket from the announce handshake and adds scanner-specific state.
    """

    def __init__(self, sock: socket.socket) -> None:
        super().__init__(sock)
        self.name: str = ""
        self.parameters: dict = {}
        self.interfaces: list[str] = []
        self.active_interfaces: list[str] = []

    def first_connection_setup(self, announce_message: dict) -> None:
        self.name = announce_message.get("name", "")
        self.parameters = announce_message.get("parameters", {})
        self.interfaces = announce_message.get("interfaces", [])
        self.active_interfaces = []

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "available_interfaces": self.interfaces,
            "active_interfaces": self.active_interfaces,
            "parameters": self.parameters,
        }

    @classmethod
    def promote(cls, conn: MsgSocket) -> Self:
        conn.__class__ = cls
        return conn


class DiscoveryServer:
    # Maps scanner name -> module path for scanners the server knows how to launch.
    _builtin_scanners = {
        "test": "discovery.scanners.test_scanner",
        "mdns": "discovery.scanners.mdns",
    }

    def open_server_socket(
        self,
        unix_path: Optional[Path] = None,
        tcp_socket: Optional[tuple[str, int]] = None,
    ) -> None:
        """
        Open the socket that clients and scanners connect through.
        unix_path is the socket file path (not a parent directory).
        Defaults to $XDG_RUNTIME_DIR/discovery or /tmp/glopmanuf/discovery.
        """
        if tcp_socket:
            host, port = tcp_socket
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            self.socket = socket.socket(family, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.info(f"Opening discovery server socket on {host}:{port}")
            self.socket.bind((host, port))
            self.socket_path = None
            self._connection_args = ["--tcp-socket", f"{host}:{port}"]
        else:
            if unix_path is None:
                if "XDG_RUNTIME_DIR" in os.environ:
                    unix_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "discovery"
                else:
                    unix_path = Path("/tmp/glopmanuf/discovery")

            unix_path.parent.mkdir(exist_ok=True, parents=True)
            self.socket = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.info(f"Opening discovery server socket at {unix_path}")
            self.socket.bind(unix_path.as_posix())
            self.socket_path = unix_path
            self._connection_args = ["--unix-socket", str(unix_path)]

        self.socket.listen()

    def start(
        self,
        unix_path: Optional[Path] = None,
        tcp_socket: Optional[tuple[str, int]] = None,
        persistent: bool = False,
    ) -> None:
        self._persistent = persistent
        try:
            self.open_server_socket(unix_path=unix_path, tcp_socket=tcp_socket)
            self.main_loop()
        finally:
            for conn in self.unannounced_connections + self.clients + self.scanners:
                conn.close()
            self.socket.close()
            if self.socket_path:
                os.unlink(self.socket_path)

    def stop(self):
        self._continue_running = False

    def main_loop(self):
        self.unannounced_connections: list[MsgSocket] = []
        self.clients: list[MsgSocket] = []
        self.scanners: list[ScannerConnection] = []
        self._continue_running = True

        while self._continue_running:
            all_connections = (
                self.unannounced_connections + self.clients + self.scanners
            )
            wait_until_read = [self.socket] + all_connections
            wait_until_write = [c for c in all_connections if c.msg_data_write_queued()]
            wait_until_exception = []
            # Timeout allows the loop condition to be checked periodically so a
            # signal handler that clears _running isn't ignored by PEP 475 syscall restart.
            ready_to_read, ready_to_write, exceptional = select(
                wait_until_read, wait_until_write, wait_until_exception, 0.5
            )

            for s in ready_to_write:
                s.flush_write_buf()

            for s in ready_to_read:
                if s == self.socket:
                    sock, _addr = self.socket.accept()
                    self.unannounced_connections.append(MsgSocket(sock))
                    logger.debug(f"New connection from {_addr}")
                elif s in self.unannounced_connections:
                    try:
                        msgs: list[str] = s.read_msgs()
                        logger.debug(f"New Connection has delivered {len(msgs)} messages")
                        self._handle_unannounced_msgs(s, msgs)
                    except ConnectionError:
                        logger.info("    Disconnecting Unannounced Connection")
                        self.unannounced_connections.remove(s)
                elif s in self.clients:
                    try:
                        msgs: list[str] = s.read_msgs()
                        logger.debug(f"Client has delivered {len(msgs)} messages")
                        self._handle_client_msgs(s, msgs)
                    except ConnectionError:
                        logger.info("    Disconnecting Client Connection")
                        self.clients.remove(s)
                        if not self._persistent and len(self.clients) == 0:
                            logger.info("Last client disconnected, shutting down")
                            self.stop()
                elif s in self.scanners:
                    assert isinstance(s, ScannerConnection)
                    try:
                        msgs: list[str] = s.read_msgs()
                        logger.debug(f"    {msgs}")
                        self._handle_scanner_msgs(s, msgs)
                    except ConnectionError:
                        logger.info(f"    Disconnecting Scanner {s.name!r}")
                        self.scanners.remove(s)
                        self._broadcast_to_clients({
                            "command": "available_scanners_changed",
                            "scanners": [sc.name for sc in self.scanners],
                        })
                else:
                    logger.error(f"Unknown socket returned from select read list {s}", stack_info=True)

    def _find_scanner(self, name: str) -> Optional[ScannerConnection]:
        for sc in self.scanners:
            if sc.name == name:
                return sc
        return None

    def _broadcast_to_clients(self, msg: dict) -> None:
        raw = json.dumps(msg)
        for client in self.clients:
            client.send_msg(raw)

    def _handle_unannounced_msgs(self, conn: MsgSocket, messages: list[str]):
        for raw in messages:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Received non-JSON message: {raw!r}")
                continue
            match msg.get("command"):
                case "announce":
                    match msg.get("type"):
                        case "scanner":
                            scanner_name = msg.get("name", "")
                            if self._find_scanner(scanner_name) is not None:
                                logger.warning(f"Rejected duplicate scanner announce for {scanner_name!r}")
                                conn.send_msg(json.dumps({
                                    "command": "status",
                                    "status": "rejected",
                                    "reason": f"A scanner named {scanner_name!r} is already registered",
                                }))
                                continue
                            self.unannounced_connections.remove(conn)
                            scanner_conn = ScannerConnection.promote(conn)
                            scanner_conn.first_connection_setup(msg)
                            self.scanners.append(scanner_conn)
                            logger.info(
                                f"Scanner announced: {scanner_conn.name!r} with interfaces {scanner_conn.interfaces}"
                            )
                            scanner_conn.send_msg(json.dumps({
                                "command": "status",
                                "status": "accepted",
                                "server_api_version": 1,
                            }))
                            self._broadcast_to_clients({
                                "command": "available_scanners_changed",
                                "scanners": [sc.name for sc in self.scanners],
                            })
                        case "client":
                            self.unannounced_connections.remove(conn)
                            self.clients.append(conn)
                            logger.info("Client announced")
                            conn.send_msg(json.dumps({
                                "command": "status",
                                "status": "accepted",
                                "server_api_version": 1,
                                "scanners": [sc.name for sc in self.scanners],
                            }))
                        case unknown:
                            logger.warning(f"Announce with unknown type: {unknown!r}")
                case unknown:
                    logger.warning(
                        f"Unknown command from unannounced connection: {unknown!r}"
                    )

    def _handle_client_msgs(self, conn: MsgSocket, messages: list[str]):
        for raw in messages:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Received non-JSON message from client: {raw!r}")
                continue

            command = msg.get("command")
            logger.debug(f"Client command: {command!r}")

            match command:

                case "get_builtin_scanners":
                    conn.send_msg(json.dumps({
                        "command": "status",
                        "status": "accepted",
                        "scanners": list(self._builtin_scanners.keys()),
                    }))

                case "get_registered_scanners":
                    conn.send_msg(json.dumps({
                        "command": "status",
                        "status": "accepted",
                        "scanners": [sc.to_dict() for sc in self.scanners],
                    }))

                case "get_registered_scanner":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                    else:
                        conn.send_msg(json.dumps({"command": "status", "status": "accepted", **sc.to_dict()}))

                case "get_scanner_available_interfaces":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                    else:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "accepted",
                            "interfaces": sc.interfaces,
                        }))

                case "get_scanner_active_interfaces":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                    else:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "accepted",
                            "interfaces": sc.active_interfaces,
                        }))

                case "get_scanner_parameters":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                    else:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "accepted",
                            "parameters": sc.parameters,
                        }))

                case "set_active_interfaces":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                        continue
                    requested = msg.get("interfaces", [])
                    unknown = [iface for iface in requested if iface not in sc.interfaces]
                    if unknown:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Interfaces not reported as available by scanner: {unknown}",
                            "interfaces": unknown,
                        }))
                        continue
                    conn.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    sc.send_msg(json.dumps({"command": "set_active_interfaces", "interfaces": requested}))

                case "set_scanner_parameters":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                        continue
                    params = msg.get("parameters", [])
                    unknown = [p["name"] for p in params if p.get("name") not in sc.parameters]
                    if unknown:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Unknown parameter names: {unknown}",
                            "parameters": unknown,
                        }))
                        continue
                    conn.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    sc.send_msg(json.dumps({"command": "set_scanner_parameters", "parameters": params}))

                case "stop_scanner":
                    sc = self._find_scanner(msg.get("scanner", ""))
                    if sc is None:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanner {msg.get('scanner')!r} is not registered",
                        }))
                        continue
                    conn.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    sc.send_msg(json.dumps({"command": "stop_scanner"}))

                case "clear_cache":
                    scanner_names = msg.get("scanners", [])
                    unknown = [name for name in scanner_names if self._find_scanner(name) is None]
                    if unknown:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"Scanners not registered: {unknown}",
                            "scanners": unknown,
                        }))
                        continue
                    conn.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    for name in scanner_names:
                        sc = self._find_scanner(name)
                        assert sc is not None
                        sc.send_msg(json.dumps({"command": "clear_cache"}))

                case "start_builtin_scanner":
                    name = msg.get("scanner", "")
                    if name not in self._builtin_scanners:
                        conn.send_msg(json.dumps({
                            "command": "status",
                            "status": "rejected",
                            "reason": f"{name!r} is not a known built-in scanner",
                        }))
                        continue
                    module_path = self._builtin_scanners[name]
                    module = importlib.import_module(module_path)
                    args = [sys.executable, module.__file__] + self._connection_args
                    subprocess.Popen(args, start_new_session=True)
                    conn.send_msg(json.dumps({"command": "status", "status": "accepted"}))

                case unknown:
                    logger.warning(f"Unknown command from client: {unknown!r}")

    def _handle_scanner_msgs(self, scanner: ScannerConnection, messages: list[str]):
        for raw in messages:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Received non-JSON message from scanner {scanner.name!r}: {raw!r}")
                continue

            command = msg.get("command")
            logger.debug(f"Scanner {scanner.name!r} command: {command!r}")

            match command:

                case "available_interfaces_changed":
                    scanner.interfaces = msg.get("interfaces", [])
                    scanner.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    self._broadcast_to_clients({
                        "command": "available_interfaces_changed",
                        "scanner": scanner.name,
                        "interfaces": scanner.interfaces,
                    })

                case "active_interfaces_changed":
                    scanner.active_interfaces = msg.get("interfaces", [])
                    scanner.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    self._broadcast_to_clients({
                        "command": "active_interfaces_changed",
                        "scanner": scanner.name,
                        "interfaces": scanner.active_interfaces,
                    })

                case "parameters_changed":
                    # Merge the list[dict] of name/value pairs into the flat parameters cache.
                    for entry in msg.get("parameters", []):
                        scanner.parameters[entry["name"]] = entry["value"]
                    scanner.send_msg(json.dumps({"command": "status", "status": "accepted"}))
                    self._broadcast_to_clients({
                        "command": "parameters_changed",
                        "scanner": scanner.name,
                        "parameters": msg.get("parameters", []),
                    })

                case unknown:
                    logger.warning(f"Unknown command from scanner {scanner.name!r}: {unknown!r}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Discovery server")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unix-socket", type=Path, metavar="PATH")
    group.add_argument("--tcp-socket", type=_parse_tcp_socket, metavar="HOST:PORT")
    parser.add_argument("--persistent", action="store_true",
                        help="Keep the server running after the last client disconnects")
    parsed_args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    server = DiscoveryServer()

    def _handle_sigint(signum, frame):
        logger.info("SIGINT received, shutting down")
        server.stop()

    signal.signal(signal.SIGINT, _handle_sigint)
    server.start(unix_path=parsed_args.unix_socket, tcp_socket=parsed_args.tcp_socket, persistent=parsed_args.persistent)
