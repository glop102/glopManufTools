"""
DiscoveryWorker — QThread that owns the DiscoveryClient socket loop.

All blocking I/O lives here; data is pushed to the main thread via Qt signals.
"""

import logging
import queue
import time
from collections import deque
from select import select

from PyQt6.QtCore import QThread, pyqtSignal

from discovery.client import DiscoveryClient
from discovery.commands import (
    ClientAnnounce,
    ClientGetBuiltinScanners,
    ClientGetRegisteredScanner,
    ClientGetResults,
    ClientSetActiveInterfaces,
    ClientStartBuiltinScanner,
    ClientStopScanner,
    ServerAvailableInterfacesChanged,
    ServerAvailableScannersChanged,
    ServerResultsRemove,
    ServerResultsUpdate,
    ServerToClientMessageAdapter,
    StatusResponse,
)
from pydantic import BaseModel

logger = logging.getLogger("discovery_applet.worker")

_STARTUP_TIMEOUT = 5.0  # seconds to wait for a scanner to appear


class DiscoveryWorker(QThread):
    hosts_updated = pyqtSignal(str, dict)   # key, MDNSHostData-dict
    hosts_removed = pyqtSignal(list)        # list[str] of keys
    status_changed = pyqtSignal(str)        # "connecting" | "connected" | "error: ..."
    scanners_changed = pyqtSignal(list, list)  # running: list[str], builtins: list[str]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cmd_queue: queue.SimpleQueue[BaseModel] = queue.SimpleQueue()
        self._active_scanners: list[str] = []
        self._builtin_scanners: list[str] = []

    def stop_all_scanners(self) -> None:
        """Thread-safe: request that all known scanners be stopped."""
        for scanner in list(self._active_scanners):
            self._cmd_queue.put(ClientStopScanner(scanner=scanner))

    def stop_scanner(self, name: str) -> None:
        """Thread-safe: request that a specific scanner be stopped."""
        self._cmd_queue.put(ClientStopScanner(scanner=name))

    def start_builtin_scanner(self, name: str) -> None:
        """Thread-safe: request that a builtin scanner be started."""
        self._cmd_queue.put(ClientStartBuiltinScanner(scanner=name))

    def run(self) -> None:
        self.status_changed.emit("connecting")
        self._buf: deque[dict] = deque()

        try:
            client = DiscoveryClient.connect(spawn_if_missing=True)
        except Exception as exc:
            logger.error("Failed to connect to discovery server", exc_info=exc)
            self.status_changed.emit(f"error: {exc}")
            return

        try:
            self._setup(client)
            self._loop(client)
        except Exception as exc:
            logger.error("Worker error", exc_info=exc)
            self.status_changed.emit(f"error: {exc}")
        finally:
            client.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fill_buf(self, client, timeout: float = 5.0) -> None:
        """Read from socket into the message buffer, waiting up to timeout."""
        ready, _, _ = select([client], [], [], timeout)
        if not ready:
            raise RuntimeError(f"Timed out after {timeout}s waiting for server response")
        msgs = client.read_msgs()
        if not msgs:
            raise RuntimeError("Connection closed before a message was received")
        self._buf.extend(msgs)

    def _recv(self, client, timeout: float = 5.0) -> dict:
        """Return the next raw buffered message dict, refilling from the socket if needed."""
        if not self._buf:
            self._fill_buf(client, timeout)
        return self._buf.popleft()

    def _recv_parsed(self, client, timeout: float = 5.0):
        """Return the next buffered message parsed into a pydantic model."""
        return ServerToClientMessageAdapter.validate_python(self._recv(client, timeout))

    def _setup(self, client) -> None:
        """Announce, ensure mdns.v1 is running, activate interfaces, seed UI."""
        # 1. Announce
        client.send_cmd(ClientAnnounce())
        resp = self._recv_parsed(client)
        assert isinstance(resp, StatusResponse)
        current_scanners: list[str] = resp.model_extra.get("scanners", [])
        self._active_scanners = list(current_scanners)

        # 2. Fetch the list of builtin scanners from the server
        client.send_cmd(ClientGetBuiltinScanners())
        builtins_resp = self._recv_parsed(client)
        assert isinstance(builtins_resp, StatusResponse)
        self._builtin_scanners = builtins_resp.model_extra.get("scanners", [])

        # 3. Start mdns.v1 if not already running, otherwise seed UI from running scanners
        if "mdns.v1" not in current_scanners:
            self._do_start_scanner(client, "mdns.v1")
            return  # _do_start_scanner emits status_changed and scanners_changed

        for name in current_scanners:
            client.send_cmd(ClientGetRegisteredScanner(scanner=name))
            scanner_info = self._recv_parsed(client)
            assert isinstance(scanner_info, StatusResponse)
            available: list[str] = scanner_info.model_extra.get("available_interfaces", [])
            active = [iface for iface in available if not iface.startswith("lo")]
            if active:
                client.send_cmd(ClientSetActiveInterfaces(scanner=name, interfaces=active))
                self._recv_parsed(client)  # consume status: accepted
            client.send_cmd(ClientGetResults(scanner=name))
            results_resp = self._recv_parsed(client)
            assert isinstance(results_resp, StatusResponse)
            for item in results_resp.model_extra.get("results", []):
                self.hosts_updated.emit(item["key"], item["result"])

        self.status_changed.emit("connected")
        self.scanners_changed.emit(list(self._active_scanners), list(self._builtin_scanners))

    def _wait_for_scanner(self, client, scanner_name: str) -> bool:
        """
        Drain messages until available_scanners_changed includes scanner_name,
        or the timeout elapses. Returns True if found.
        """
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            # Drain any already-buffered messages first
            while self._buf:
                raw = self._buf.popleft()
                msg = ServerToClientMessageAdapter.validate_python(raw)
                if isinstance(msg, ServerAvailableScannersChanged) and scanner_name in msg.scanners:
                    return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._fill_buf(client, timeout=min(remaining, 0.5))
            except RuntimeError:
                pass  # timeout on this iteration is fine, keep looping
        return False

    def _do_start_scanner(self, client, name: str) -> None:
        """Start a builtin scanner, activate its interfaces, and seed the UI with existing results."""
        if name in self._active_scanners:
            logger.info("%s is already running, ignoring start request", name)
            return

        logger.info("Starting %s scanner", name)
        client.send_cmd(ClientStartBuiltinScanner(scanner=name))
        start_resp = self._recv_parsed(client)
        assert isinstance(start_resp, StatusResponse)
        if start_resp.status != "accepted":
            logger.error("start_builtin_scanner rejected: %s", start_resp)
            self.status_changed.emit(f"error: {name} start rejected")
            return

        if not self._wait_for_scanner(client, name):
            logger.error("%s did not start within timeout", name)
            self.status_changed.emit(f"error: {name} start timed out")
            return

        self._active_scanners.append(name)

        client.send_cmd(ClientGetRegisteredScanner(scanner=name))
        scanner_info = self._recv_parsed(client)
        assert isinstance(scanner_info, StatusResponse)
        available: list[str] = scanner_info.model_extra.get("available_interfaces", [])
        active = [iface for iface in available if not iface.startswith("lo")]
        if active:
            client.send_cmd(ClientSetActiveInterfaces(scanner=name, interfaces=active))
            self._recv_parsed(client)  # consume status: accepted

        client.send_cmd(ClientGetResults(scanner=name))
        results_resp = self._recv_parsed(client)
        assert isinstance(results_resp, StatusResponse)
        for item in results_resp.model_extra.get("results", []):
            self.hosts_updated.emit(item["key"], item["result"])

        self.status_changed.emit("connected")
        self.scanners_changed.emit(list(self._active_scanners), list(self._builtin_scanners))

    def _loop(self, client) -> None:
        """Main event loop — forwards scan results to the UI thread via signals."""
        while not self.isInterruptionRequested():
            # Drain any commands queued from the main thread
            while not self._cmd_queue.empty():
                try:
                    cmd = self._cmd_queue.get_nowait()
                except queue.Empty:
                    break
                if isinstance(cmd, ClientStartBuiltinScanner):
                    self._do_start_scanner(client, cmd.scanner)
                else:
                    client.send_cmd(cmd)
                    self._recv_parsed(client, timeout=2.0)  # consume the status reply

            # Process any messages already in the buffer before blocking on select
            while self._buf:
                self._handle_msg(client, ServerToClientMessageAdapter.validate_python(self._buf.popleft()))

            ready, _, _ = select([client], [], [], 0.5)
            if not ready:
                continue

            try:
                msgs = client.read_msgs()
            except ConnectionError:
                logger.info("Server connection closed")
                self.status_changed.emit("error: server disconnected")
                break

            for raw in msgs:
                self._handle_msg(client, ServerToClientMessageAdapter.validate_python(raw))

    def _handle_msg(self, client, msg) -> None:
        match msg:
            case ServerResultsUpdate():
                for item in msg.results:
                    self.hosts_updated.emit(item.key, item.result)
            case ServerResultsRemove():
                if msg.keys:
                    self.hosts_removed.emit(msg.keys)
            case ServerAvailableScannersChanged():
                self._active_scanners = list(msg.scanners)
                self.scanners_changed.emit(list(self._active_scanners), list(self._builtin_scanners))
            case ServerAvailableInterfacesChanged():
                active = [i for i in msg.interfaces if not i.startswith("lo")]
                if active:
                    client.send_cmd(ClientSetActiveInterfaces(scanner="mdns.v1", interfaces=active))
            case _:
                pass
