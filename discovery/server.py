import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import socket_spawner

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

        # Try to make sure the unix socket folder exists for us to bind into
        if not path.exists():
            path.mkdir(exist_ok=True,parents=True)

        # Open a unix socket on the system for other client services to connect to
        self.socket = socket.socket(
            family=socket.AF_UNIX,
            type=socket.SOCK_STREAM,
        )
        # Probably lets you re-use a unix socket if the file is already there and the server is not activly bound to it?
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Actually put the socket at the intended path
        self.socket.bind((path/"discovery").as_posix())
        self.socket_path = path/"discovery"

        return self.socket_path

    def spawn_socket_spawner(self):
        subprocess.Popen(
            [
                sys.executable,
                socket_spawner.__file__,
                "--socket-path",
                self.socket_path,
            ],
            start_new_session=True,
        )

    def __init__(self):
        self.open_server_socket()

        # Spawn socket opening services and have it connect to the management socket by passing it the path argument to the socket
        self.spawn_socket_spawner()

        # Main loop of listening for clients connecting
        # 2 lists and a special var
        # - unannounced connections -> if nothing for 2 seconds, close the connection
        # - clients -> the send in a response telling us they are a client  with an {"announce":"client"}\0
        # - socket_spawner -> single var holder and we error if someone else announces and it is already assigned
        try:
            self.main_loop()
        finally:
            self.socket.close()
            os.unlink(self.socket_path)
    
    def main_loop(self):
        pass