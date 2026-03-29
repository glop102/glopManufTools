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
    Wraps the accepted socket from the listening server socket and inherits
    message framing from MsgSocket. Instances can be passed directly to select().
    """

    def __init__(self, sock: socket.socket):
        super().__init__(sock)

class ClientConnection(MsgSocket):
    """
    Server-side representation of a connected client.
    Wraps the accepted socket from the listening server socket and inherits
    message framing from MsgSocket. Instances can be passed directly to select().
    """

    def __init__(self, sock: socket.socket):
        super().__init__(sock)

class DiscoveryServer:
    def open_server_socket(self,path:Optional[Path]=None) -> Path:
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
            path.mkdir(exist_ok=True,parents=True)

        self.socket = socket.socket(
            family=socket.AF_UNIX,
            type=socket.SOCK_STREAM,
        )
        # Technically does nothing for unix sockets, but leaving it here for when we eventually add in TCP connections
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logger.info(f"Opening discovery server socket at {path/"discovery"}")
        self.socket.bind((path/"discovery").as_posix())
        self.socket_path = path/"discovery"
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
        self.unannounced_connections:list[ClientConnection] = []

        while True:
            wait_until_read = [self.socket]
            wait_until_write = []
            wait_until_exception = [self.socket]
            ready_to_read, ready_to_write, exceptional = select(wait_until_read, wait_until_write, wait_until_exception)

            for s in ready_to_read:
                if s == self.socket:
                    new_connection = s.accept()
                    self.unannounced_connections.append(ClientConnection(new_connection))
                else:
                    print("Another socket type ready to read:",s)

if __name__ == "__main__":
    DiscoveryServer().start()