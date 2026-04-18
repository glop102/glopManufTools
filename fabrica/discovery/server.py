import argparse
import os
import signal
from select import select
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional, Self
import logging

from pydantic import ValidationError

from .commands import (
    AnnounceMessageAdapter,
    ClientClearCache,
    ClientGetBuiltinScanners,
    ClientGetRegisteredScanner,
    ClientGetRegisteredScanners,
    ClientGetResult,
    ClientGetResults,
    ClientGetScannerActiveInterfaces,
    ClientGetScannerAvailableInterfaces,
    ClientGetScannerParameters,
    ClientMessageAdapter,
    ClientSetActiveInterfaces,
    ClientSetScannerParameters,
    ClientStartBuiltinScanner,
    ClientStopScanner,
    ParameterUpdate,
    ScannerActiveInterfacesChanged,
    ScannerAnnounce,
    ScannerAvailableInterfacesChanged,
    ScannerMessageAdapter,
    ScannerParametersChanged,
    ScannerResultsRemove,
    ScannerResultsUpdate,
    ScanResultItem,
    ServerActiveInterfacesChanged,
    ServerAvailableInterfacesChanged,
    ServerAvailableScannersChanged,
    ServerClearCache,
    ServerParametersChanged,
    ServerResultsRemove,
    ServerResultsUpdate,
    ServerSetActiveInterfaces,
    ServerSetScannerParameters,
    ServerStopScanner,
    StatusResponse,
)
from .msg_socket import MsgSocket
from ._utils import _parse_tcp_socket

logger = logging.getLogger("fabrica.discovery")



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
        self.results: dict[str, dict] = {}  # key -> serialized result dict

    def first_connection_setup(self, announce: ScannerAnnounce) -> None:
        self.name = announce.name
        self.parameters = announce.parameters
        self.interfaces = announce.interfaces
        self.active_interfaces = []
        self.results = {}

    @classmethod
    def promote(cls, conn: MsgSocket) -> Self:
        conn.__class__ = cls
        return conn


class DiscoveryServer:
    # Maps scanner name -> module path for scanners the server knows how to launch.
    _builtin_scanners = {
        "test": "fabrica.discovery.scanners.test_scanner",
        "mdns.v1": "fabrica.discovery.scanners.mdns",
        "lldp.v1": "fabrica.discovery.scanners.lldp",
    }

    def __init__(self):
        self.unannounced_connections: list[MsgSocket] = []
        self.clients: list[MsgSocket] = []
        self.scanners: list[ScannerConnection] = []
        self.socket_path: Optional[Path] = None

    def open_server_socket(
        self,
        unix_path: Optional[Path] = None,
        tcp_socket: Optional[tuple[str, int]] = None,
    ) -> None:
        """
        Open the socket that clients and scanners connect through.
        unix_path is the socket file path (not a parent directory).
        Defaults to $XDG_RUNTIME_DIR/fabrica_discovery or /tmp/glopmanuf/fabrica_discovery.
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
                    unix_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "fabrica_discovery"
                else:
                    unix_path = Path("/tmp/glopmanuf/fabrica_discovery")

            unix_path.parent.mkdir(exist_ok=True, parents=True)
            if unix_path.exists():
                # Probe for a live server; unlink the file if it's stale.
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.connect(unix_path.as_posix())
                    probe.close()
                    raise OSError(f"Another discovery server is already listening at {unix_path}")
                except ConnectionRefusedError:
                    unix_path.unlink()
                finally:
                    probe.close()
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
            ready_to_read, ready_to_write, _exceptional = select(
                wait_until_read, wait_until_write, wait_until_exception, 0.5
            )

            for s in ready_to_write:
                try:
                    s.flush_write_buf()
                except ConnectionError:
                    if s in self.unannounced_connections:
                        logger.info("Disconnecting Unannounced Connection (write error)")
                        self.unannounced_connections.remove(s)
                    elif s in self.clients:
                        logger.info("Disconnecting Client Connection (write error)")
                        self.clients.remove(s)
                        if not self._persistent and len(self.clients) == 0:
                            logger.info("Last client disconnected, shutting down")
                            self.stop()
                    elif s in self.scanners:
                        assert isinstance(s, ScannerConnection)
                        logger.info(f"Disconnecting Scanner {s.name!r} (write error)")
                        self._disconnect_scanner(s)

            for s in ready_to_read:
                if s == self.socket:
                    sock, _addr = self.socket.accept()
                    self.unannounced_connections.append(MsgSocket(sock))
                    logger.debug(f"New connection from {_addr}")
                elif s in self.unannounced_connections:
                    try:
                        msgs: list[dict] = s.read_msgs()
                        logger.debug(
                            f"New Connection has delivered {len(msgs)} messages"
                        )
                        self._handle_unannounced_msgs(s, msgs)
                    except ConnectionError:
                        logger.info("    Disconnecting Unannounced Connection")
                        self.unannounced_connections.remove(s)
                elif s in self.clients:
                    try:
                        msgs: list[dict] = s.read_msgs()
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
                        msgs: list[dict] = s.read_msgs()
                        logger.debug(f"    {msgs}")
                        self._handle_scanner_msgs(s, msgs)
                    except ConnectionError:
                        logger.info(f"    Disconnecting Scanner {s.name!r}")
                        self._disconnect_scanner(s)
                else:
                    logger.error(
                        f"Unknown socket returned from select read list {s}",
                        stack_info=True,
                    )

    def _lookup_registered_scanner(self, name: str) -> Optional[ScannerConnection]:
        for sc in self.scanners:
            if sc.name == name:
                return sc
        return None

    def _disconnect_scanner(self, sc: "ScannerConnection") -> None:
        self.scanners.remove(sc)
        if sc.results:
            keys = list(sc.results.keys())
            sc.results.clear()
            self._broadcast_to_clients_cmd(ServerResultsRemove(scanner=sc.name, keys=keys))
        self._broadcast_to_clients_cmd(ServerAvailableScannersChanged(scanners=[s.name for s in self.scanners]))

    def _broadcast_to_clients_cmd(self, model) -> None:
        for client in self.clients:
            try:
                client.send_cmd(model, send_synchronous=False)
            except ConnectionError:
                logger.info("Client disconnected during broadcast, will be cleaned up by main loop")

    def _handle_unannounced_msgs(self, conn: MsgSocket, messages: list[dict]):
        for raw in messages:
            if raw.get("command") != "announce":
                logger.warning(f"Unknown command from unannounced connection: {raw.get('command')!r}")
                conn.send_cmd(StatusResponse(status="rejected", reason=f"Expected announce, got {raw.get('command')!r}"), send_synchronous=False)
                continue
            try:
                msg = AnnounceMessageAdapter.validate_python(raw)
            except ValidationError:
                logger.warning(f"Invalid announce message: {raw!r}")
                conn.send_cmd(StatusResponse(status="rejected", reason="Malformed announce message"), send_synchronous=False)
                continue
            if isinstance(msg, ScannerAnnounce):
                if self._lookup_registered_scanner(msg.name) is not None:
                    logger.warning(f"Rejected duplicate scanner announce for {msg.name!r}")
                    conn.send_cmd(StatusResponse(status="rejected", reason=f"A scanner named {msg.name!r} is already registered"), send_synchronous=False)
                    continue
                self.unannounced_connections.remove(conn)
                scanner_conn = ScannerConnection.promote(conn)
                scanner_conn.first_connection_setup(msg)
                self.scanners.append(scanner_conn)
                logger.info(f"Scanner announced: {scanner_conn.name!r} with interfaces {scanner_conn.interfaces}")
                scanner_conn.send_cmd(StatusResponse(status="accepted", server_api_version=1), send_synchronous=False)
                self._broadcast_to_clients_cmd(ServerAvailableScannersChanged(scanners=[sc.name for sc in self.scanners]))
            else:
                # ClientAnnounce
                self.unannounced_connections.remove(conn)
                self.clients.append(conn)
                logger.info("Client announced")
                conn.send_cmd(StatusResponse(status="accepted", server_api_version=1, scanners=[sc.name for sc in self.scanners]), send_synchronous=False)

    def _handle_client_msgs(self, conn: MsgSocket, messages: list[dict]):
        for raw in messages:
            logger.debug(f"Client command: {raw.get('command')!r}")
            try:
                msg = ClientMessageAdapter.validate_python(raw)
            except ValidationError:
                logger.warning(f"Unknown/invalid command from client: {raw.get('command')!r}")
                conn.send_cmd(StatusResponse(status="rejected", reason=f"Unknown or malformed command: {raw.get('command')!r}"), send_synchronous=False)
                continue

            match msg:
                case ClientGetBuiltinScanners():
                    conn.send_cmd(StatusResponse(status="accepted", scanners=list(self._builtin_scanners.keys())), send_synchronous=False)

                case ClientGetRegisteredScanners():
                    conn.send_cmd(StatusResponse(status="accepted", scanners=[
                        {
                            "name": sc.name,
                            "available_interfaces": sc.interfaces,
                            "active_interfaces": sc.active_interfaces,
                            "parameters": sc.parameters,
                        }
                        for sc in self.scanners
                    ]), send_synchronous=False)

                case ClientGetRegisteredScanner():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        conn.send_cmd(StatusResponse(
                            status="accepted",
                            name=sc.name,
                            available_interfaces=sc.interfaces,
                            active_interfaces=sc.active_interfaces,
                            parameters=sc.parameters,
                        ), send_synchronous=False)

                case ClientGetScannerAvailableInterfaces():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        conn.send_cmd(StatusResponse(status="accepted", interfaces=sc.interfaces), send_synchronous=False)

                case ClientGetScannerActiveInterfaces():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        conn.send_cmd(StatusResponse(status="accepted", interfaces=sc.active_interfaces), send_synchronous=False)

                case ClientGetScannerParameters():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        conn.send_cmd(StatusResponse(status="accepted", parameters=sc.parameters), send_synchronous=False)

                case ClientSetActiveInterfaces():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                        continue
                    unknown = [iface for iface in msg.interfaces if iface not in sc.interfaces]
                    if unknown:
                        conn.send_cmd(StatusResponse(
                            status="rejected",
                            reason=f"Interfaces not reported as available by scanner: {unknown}",
                            interfaces=unknown,
                        ), send_synchronous=False)
                        continue
                    conn.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    sc.send_cmd(ServerSetActiveInterfaces(interfaces=msg.interfaces), send_synchronous=False)

                case ClientSetScannerParameters():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                        continue
                    unknown = [p.name for p in msg.parameters if p.name not in sc.parameters]
                    if unknown:
                        conn.send_cmd(StatusResponse(
                            status="rejected",
                            reason=f"Unknown parameter names: {unknown}",
                            parameters=unknown,
                        ), send_synchronous=False)
                        continue
                    conn.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    sc.send_cmd(ServerSetScannerParameters(parameters=msg.parameters), send_synchronous=False)

                case ClientStopScanner():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                        continue
                    conn.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    sc.send_cmd(ServerStopScanner(), send_synchronous=False)

                case ClientClearCache():
                    unknown = [name for name in msg.scanners if self._lookup_registered_scanner(name) is None]
                    if unknown:
                        conn.send_cmd(StatusResponse(
                            status="rejected",
                            reason=f"Scanners not registered: {unknown}",
                            scanners=unknown,
                        ), send_synchronous=False)
                        continue
                    conn.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    for name in msg.scanners:
                        sc = self._lookup_registered_scanner(name)
                        assert sc is not None
                        if sc.results:
                            keys = list(sc.results.keys())
                            sc.results.clear()
                            self._broadcast_to_clients_cmd(ServerResultsRemove(scanner=name, keys=keys))
                        sc.send_cmd(ServerClearCache(), send_synchronous=False)

                case ClientGetResults():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        conn.send_cmd(StatusResponse(
                            status="accepted",
                            results=[{"key": k, "result": v} for k, v in sc.results.items()],
                        ), send_synchronous=False)

                case ClientGetResult():
                    sc = self._lookup_registered_scanner(msg.scanner)
                    if sc is None:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"Scanner {msg.scanner!r} is not registered"), send_synchronous=False)
                    else:
                        result = sc.results.get(msg.key)
                        if result is None:
                            conn.send_cmd(StatusResponse(status="rejected", reason=f"Key {msg.key!r} not found in scanner {sc.name!r}"), send_synchronous=False)
                        else:
                            conn.send_cmd(StatusResponse(status="accepted", key=msg.key, result=result), send_synchronous=False)

                case ClientStartBuiltinScanner():
                    if msg.scanner not in self._builtin_scanners:
                        conn.send_cmd(StatusResponse(status="rejected", reason=f"{msg.scanner!r} is not a known built-in scanner"), send_synchronous=False)
                        continue
                    module_path = self._builtin_scanners[msg.scanner]
                    args = [sys.executable, "-m", module_path] + self._connection_args
                    subprocess.Popen(args, start_new_session=True)
                    conn.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)

    def _handle_scanner_msgs(self, scanner: ScannerConnection, messages: list[dict]):
        for raw in messages:
            logger.debug(f"Scanner {scanner.name!r} command: {raw.get('command')!r}")
            try:
                msg = ScannerMessageAdapter.validate_python(raw)
            except ValidationError:
                logger.warning(f"Unknown/invalid command from scanner {scanner.name!r}: {raw.get('command')!r}")
                scanner.send_cmd(StatusResponse(status="rejected", reason=f"Unknown or malformed command: {raw.get('command')!r}"), send_synchronous=False)
                continue

            match msg:
                case ScannerAvailableInterfacesChanged():
                    scanner.interfaces = msg.interfaces
                    scanner.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    self._broadcast_to_clients_cmd(ServerAvailableInterfacesChanged(scanner=scanner.name, interfaces=scanner.interfaces))

                case ScannerActiveInterfacesChanged():
                    scanner.active_interfaces = msg.interfaces
                    scanner.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    self._broadcast_to_clients_cmd(ServerActiveInterfacesChanged(scanner=scanner.name, interfaces=scanner.active_interfaces))

                case ScannerParametersChanged():
                    for entry in msg.parameters:
                        scanner.parameters[entry.name] = entry.value
                    scanner.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    self._broadcast_to_clients_cmd(ServerParametersChanged(scanner=scanner.name, parameters=msg.parameters))

                case ScannerResultsUpdate():
                    for item in msg.results:
                        scanner.results[item.key] = item.result
                    scanner.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    if msg.results:
                        self._broadcast_to_clients_cmd(ServerResultsUpdate(scanner=scanner.name, results=msg.results))

                case ScannerResultsRemove():
                    removed_keys = [k for k in msg.keys if k in scanner.results]
                    for key in removed_keys:
                        del scanner.results[key]
                    scanner.send_cmd(StatusResponse(status="accepted"), send_synchronous=False)
                    self._broadcast_to_clients_cmd(ServerResultsRemove(scanner=scanner.name, keys=removed_keys))

                case ScannerAnnounce():
                    logger.warning(f"Received duplicate announce from already-registered scanner {scanner.name!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Discovery server")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unix-socket", type=Path, metavar="PATH")
    group.add_argument("--tcp-socket", type=_parse_tcp_socket, metavar="HOST:PORT")
    parser.add_argument(
        "--persistent",
        action="store_true",
        help="Keep the server running after the last client disconnects",
    )
    parsed_args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    server = DiscoveryServer()

    def _handle_sigint(signum, frame):
        logger.info("SIGINT received, shutting down")
        server.stop()

    signal.signal(signal.SIGINT, _handle_sigint)
    server.start(
        unix_path=parsed_args.unix_socket,
        tcp_socket=parsed_args.tcp_socket,
        persistent=parsed_args.persistent,
    )
