import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from discovery.msg_socket import MsgSocket


def _default_unix_socket_path() -> Path:
    if "XDG_RUNTIME_DIR" in os.environ:
        return Path(os.environ["XDG_RUNTIME_DIR"]) / "discovery"
    return Path("/tmp/glopmanuf/discovery")


class DiscoveryClient(MsgSocket):
    @classmethod
    def connect(
        cls,
        unix_socket_path: Optional[Path] = None,
        tcp_socket: Optional[tuple[str, int]] = None,
        spawn_if_missing: bool = True,
    ) -> "DiscoveryClient":
        """
        Connect to the discovery server. If the server is not running and
        spawn_if_missing is True, fork a server process and retry with a short
        backoff. Multiple callers racing to spawn the server is safe — the
        second server process will fail to bind and exit, leaving the first one
        running.
        """
        unix_path = None if tcp_socket else (unix_socket_path or _default_unix_socket_path())

        try:
            return cls._open_connection(unix_path, tcp_socket)
        except (ConnectionRefusedError, FileNotFoundError):
            if not spawn_if_missing or tcp_socket:
                raise

        cls._spawn_server()

        for _ in range(20):
            time.sleep(0.1)
            try:
                return cls._open_connection(unix_path, tcp_socket)
            except (ConnectionRefusedError, FileNotFoundError):
                continue

        raise ConnectionError("Discovery server did not become available after spawn")

    @classmethod
    def _open_connection(
        cls,
        unix_path: Optional[Path],
        tcp_socket: Optional[tuple[str, int]],
    ) -> "DiscoveryClient":
        if tcp_socket:
            host, port = tcp_socket
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.connect((host, port))
        elif unix_path:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(unix_path.as_posix())
        else:
            raise RuntimeError("DiscoveryClient._open_connection() called without a tcp or unix socket")
        return cls(sock)

    @classmethod
    def _spawn_server(cls) -> None:
        from . import server as server_module
        subprocess.Popen(
            [sys.executable, server_module.__file__],
            start_new_session=True,
        )
