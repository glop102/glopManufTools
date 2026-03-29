import json
import os
from select import select
import socket
from pathlib import Path
from typing import Optional
import logging

from .msg_socket import MsgSocket

logger = logging.getLogger("discovery")


class ScannerConnection(MsgSocket):
    """
    Server-side representation of a connected scanner process.
    Promoted from a plain MsgSocket via __class__ assignment after the scanner
    announces itself. Call first_connection_setup() immediately after promotion
    to initialise scanner-specific state.
    """

    name: str = (
        ""  # Scanner name is generally something human readable for what it is scanning
    )
    parameters: dict[
        str, str
    ] = {}  # Configurable parameters of a scanner - eg domains of mDNS
    interfaces: list[
        str
    ] = []  # The interfaces that the scanner knows about as being available
    active_interfaces: list[
        str
    ] = []  # The list of interfaces the scanner is actively scanning

    def first_connection_setup(self, announce_message: dict):
        self.name: str = announce_message.get("name", "")
        self.parameters: dict[str, str] = announce_message.get("parameters", {})
        self.interfaces: list[str] = announce_message.get("interfaces", [])
        self.active_interfaces: list[str] = []


class DiscoveryServer:
    def open_server_socket(self, path: Optional[Path] = None) -> Path:
        """
        Attempt to open a socket for the communications to clients will happen through.
        It will be a unix socket with a primary default of the $XDG_RUNTIME_DIR if defined.
        Upon successfully opening the socket, the socket is assigned to our instance as self.socket.
        The path to the socket is also returned and assigned to self.socket_path.
        """
        if not path:
            if "XDG_RUNTIME_DIR" in os.environ:
                path = Path(os.environ["XDG_RUNTIME_DIR"])
            else:
                path = Path("/tmp/glopmanuf/")

        if not path.exists():
            path.mkdir(exist_ok=True, parents=True)

        self.socket = socket.socket(
            family=socket.AF_UNIX,
            type=socket.SOCK_STREAM,
        )
        # Technically does nothing for unix sockets, but leaving it here for when we eventually add in TCP connections
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logger.info(f"Opening discovery server socket at {path / 'discovery'}")
        self.socket.bind((path / "discovery").as_posix())
        self.socket_path = path / "discovery"
        self.socket.listen()

        return self.socket_path

    def start(self):
        try:
            self.open_server_socket()
            self.main_loop()
        finally:
            self.socket.close()
            os.unlink(self.socket_path)

    def main_loop(self):
        self.unannounced_connections: list[MsgSocket] = []
        self.clients: list[MsgSocket] = []
        self.scanners: list[ScannerConnection] = []

        while True:
            all_connections = (
                self.unannounced_connections + self.clients + self.scanners
            )
            wait_until_read = [self.socket] + all_connections
            wait_until_write = [c for c in all_connections if c.msg_data_write_queued()]
            wait_until_exception = []
            ready_to_read, ready_to_write, exceptional = select(
                wait_until_read, wait_until_write, wait_until_exception
            )

            for s in ready_to_write:
                s.flush_write_buf()

            for s in ready_to_read:
                if s == self.socket:
                    sock, _addr = self.socket.accept()
                    self.unannounced_connections.append(MsgSocket(sock))
                    logger.debug(f"New connection from {_addr}")
                elif s in self.clients or s in self.unannounced_connections:
                    logger.debug(f"Another socket type ready to read: {s}")
                    try:
                        msgs: list[str] = s.read_msgs()
                        logger.debug(f"    {msgs}")
                        self._handle_client_msgs(s, msgs)
                    except ConnectionError:
                        logger.info("    Disconnecting connection")
                        if s in self.unannounced_connections:
                            self.unannounced_connections.remove(s)
                        else:
                            self.clients.remove(s)
                else:
                    try:
                        msgs: list[str] = s.read_msgs()
                        logger.debug(f"    {msgs}")
                        self._handle_client_msgs(s, msgs)
                    except ConnectionError:
                        logger.info("    Disconnecting Scanner")
                        self.scanners.remove(s)

    def _handle_client_msgs(self, conn: MsgSocket, messages: list[str]):
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
                            conn.__class__ = ScannerConnection
                            conn.first_connection_setup(msg)
                            self.unannounced_connections.remove(conn)
                            self.scanners.append(conn)
                            logger.info(
                                f"Scanner announced: {conn.name!r} with interfaces {conn.interfaces}"
                            )
                        case unknown:
                            logger.warning(f"Announce with unknown type: {unknown!r}")
                case unknown:
                    logger.warning(
                        f"Unknown command from unannounced connection: {unknown!r}"
                    )

    def _handle_scanner_msgs(self, socket: ScannerConnection, messages: list[str]):
        pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    DiscoveryServer().start()
