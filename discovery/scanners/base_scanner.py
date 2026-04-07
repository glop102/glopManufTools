import argparse
import logging
import os
import stat
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from select import select
from typing import Optional

from discovery.client import DiscoveryClient
from discovery._utils import _parse_tcp_socket


class BaseScanner(ABC):
    """
    Base class for scanner processes.

    Typical __main__ block:

        if __name__ == "__main__":
            scanner = MyScanner()
            remaining = scanner.parse_args(sys.argv[1:])
            scanner.connect_to_server()
            scanner.start(remaining)

    If the scanner needs root to open raw sockets, call reexec(). It replaces
    the current process with a pkexec-elevated copy that reconstructs sys.path
    and sys.argv before re-running the scanner file, so library references
    survive pkexec wiping the environment.

    If a scanner does need to reexec, wait until it is asked to start scanning
    on an interface so as to only prompt the user when elevation is actually needed.
    """

    unix_socket_path: Optional[Path] = None
    tcp_socket: Optional[tuple[str, int]] = None
    server: Optional["DiscoveryClient"] = None

    def parse_connection_args(self, args: list[str]) -> list[str]:
        """
        Parse the base scanner arguments from args, assigning unix_socket_path
        or tcp_socket on this instance. Returns the arguments that were not
        consumed, for the implementor to parse in start().
        """
        parser = argparse.ArgumentParser(add_help=False)
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--unix-socket", type=Path, metavar="PATH")
        group.add_argument("--tcp-socket", type=_parse_tcp_socket, metavar="HOST:PORT")
        parsed, remaining = parser.parse_known_args(args)
        self.unix_socket_path = parsed.unix_socket
        self.tcp_socket = parsed.tcp_socket
        return remaining

    def wait_for_registration(self, timeout: float = 5.0) -> None:
        """
        Block until the server sends back {"command": "status", "status": "accepted"} following an announce.
        Raises RuntimeError on timeout or if the response is not accepted.
        """
        assert self.server is not None
        ready, _, _ = select([self.server], [], [], timeout)
        if not ready:
            raise RuntimeError(
                "Timed out waiting for registered confirmation from server"
            )
        msgs = self.server.read_msgs()
        registered = msgs[0] if msgs else {}
        if (
            registered.get("command") != "status"
            or registered.get("status") != "accepted"
        ):
            raise RuntimeError(f"Expected status accepted, got: {registered!r}")

    def connect_to_server(self):
        self.server = DiscoveryClient.connect(
            unix_socket_path=self.unix_socket_path,
            tcp_socket=self.tcp_socket,
            spawn_if_missing=False,
        )

    @abstractmethod
    def stop(self) -> None:
        """Signal the scanner to stop and clean up."""
        ...

    @abstractmethod
    def start(self, args: list[str]) -> None:
        """
        Entry point called when the scanner process launches.
        It is common to want to parse cli args to fill out the connection details for
        talking to the discovery broker server, especially if you want to use the built-in
        re-exec functionality.
        """
        ...

    def reexec(self) -> None:
        """
        Replace this process with a root-elevated copy via sudo.
        Does not return.

        Uses sudo -A (askpass) with the bundled tkinter askpass helper so a GUI
        prompt appears without requiring pkexec or a polkit policy file.
        Uses sudo -E to preserve the environment so that nix/venv library paths
        remain intact in the elevated process.
        """
        askpass_py = Path(__file__).parent.parent / "askpass.py"
        # SUDO_ASKPASS must be a single executable path, not a command string.
        # Write a copy of the askpass script with a shebang pointing to the
        # current interpreter so no shell is required.
        askpass_exe = Path(tempfile.gettempdir()) / "discovery_askpass"
        askpass_exe.write_text(f"#!{sys.executable}\n" + askpass_py.read_text())
        askpass_exe.chmod(stat.S_IRWXU)
        env = os.environ.copy()
        env["SUDO_ASKPASS"] = str(askpass_exe)
        bootstrap = (
            f"import sys; "
            f"sys.argv = {sys.argv!r}; "
            f"sys.path = {sys.path!r}; "
            f"import runpy; runpy.run_path({sys.argv[0]!r}, run_name='__main__')"
        )
        os.execvpe(
            "sudo",
            ["sudo", "-A", "-E", sys.executable, "-c", bootstrap],
            env,
        )
