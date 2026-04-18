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

from fabrica.discovery.client import DiscoveryClient
from fabrica.discovery.commands import (
    ClientAnnounce,
    ClientClearCache,
    ClientGetBuiltinScanners,
    ClientGetRegisteredScanner,
    ClientGetResults,
    ClientSetActiveInterfaces,
    ClientStartBuiltinScanner,
    ClientStopScanner,
    ServerActiveInterfacesChanged,
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
    status_changed     = pyqtSignal(str)              # "connecting" | "connected" | "error: ..."
    scanner_added      = pyqtSignal(str, list, list)  # name, available_interfaces, active_interfaces
    scanner_removed    = pyqtSignal(str)              # name
    results_updated    = pyqtSignal(str, str, object) # scanner, key, result dict
    results_removed    = pyqtSignal(str, list)        # scanner, keys
    interfaces_updated = pyqtSignal(str, list, list)  # scanner, available, active
    builtin_scanners_known = pyqtSignal(list)         # list[str] of builtin scanner names

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cmd_queue: queue.SimpleQueue[BaseModel] = queue.SimpleQueue()
        self._active_scanners: list[str] = []
        # Per-scanner interface state: name -> {"available": [...], "active": [...]}
        self._scanner_info: dict[str, dict] = {}

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

    def set_scanner_interfaces(self, scanner: str, interfaces: list[str]) -> None:
        """Thread-safe: request that a scanner's active interfaces be updated."""
        self._cmd_queue.put(ClientSetActiveInterfaces(scanner=scanner, interfaces=interfaces))

    def clear_scanner_cache(self, scanner: str) -> None:
        """Thread-safe: request that a scanner's result cache be cleared."""
        self._cmd_queue.put(ClientClearCache(scanners=[scanner]))

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
        """Announce, ensure mdns.v1 is running, and seed the UI for all running scanners."""
        client.send_cmd(ClientAnnounce())
        resp = self._recv_parsed(client)
        assert isinstance(resp, StatusResponse)
        current_scanners: list[str] = resp.model_extra.get("scanners", [])
        self._active_scanners = list(current_scanners)

        client.send_cmd(ClientGetBuiltinScanners())
        builtins_resp = self._recv_parsed(client)
        assert isinstance(builtins_resp, StatusResponse)
        self.builtin_scanners_known.emit(builtins_resp.model_extra.get("scanners", []))

        for name in current_scanners:
            self._setup_running_scanner(client, name)

        if "mdns.v1" not in current_scanners:
            self._do_start_scanner(client, "mdns.v1")

        self.status_changed.emit("connected")

    def _setup_running_scanner(self, client, name: str) -> None:
        """Query a running scanner's state, activate non-loopback interfaces, seed results."""
        client.send_cmd(ClientGetRegisteredScanner(scanner=name))
        info = self._recv_parsed(client)
        assert isinstance(info, StatusResponse)
        available: list[str] = info.model_extra.get("available_interfaces", [])
        active: list[str] = info.model_extra.get("active_interfaces", [])

        if not active:
            active = [i for i in available if not i.startswith("lo") and i != "docker0"]
            if active:
                client.send_cmd(ClientSetActiveInterfaces(scanner=name, interfaces=active))
                self._recv_parsed(client)  # consume status: accepted

        client.send_cmd(ClientGetResults(scanner=name))
        results_resp = self._recv_parsed(client)
        assert isinstance(results_resp, StatusResponse)

        self._scanner_info[name] = {"available": available, "active": active}
        self.scanner_added.emit(name, list(available), list(active))

        for item in results_resp.model_extra.get("results", []):
            self.results_updated.emit(name, item["key"], item["result"])

    def _wait_for_scanner(self, client, scanner_name: str) -> bool:
        """
        Drain messages until available_scanners_changed includes scanner_name,
        or the timeout elapses. Returns True if found.
        """
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            while self._buf:
                msg = ServerToClientMessageAdapter.validate_python(self._buf.popleft())
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
        self._setup_running_scanner(client, name)

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
                    self.results_updated.emit(msg.scanner, item.key, item.result)
            case ServerResultsRemove():
                if msg.keys:
                    self.results_removed.emit(msg.scanner, msg.keys)
            case ServerAvailableScannersChanged():
                new_set = set(msg.scanners)
                old_set = set(self._active_scanners)
                for removed in old_set - new_set:
                    self._scanner_info.pop(removed, None)
                    self.scanner_removed.emit(removed)
                self._active_scanners = list(msg.scanners)
                for added in new_set - old_set:
                    self._setup_running_scanner(client, added)
            case ServerAvailableInterfacesChanged():
                info = self._scanner_info.get(msg.scanner, {})
                prev_available = set(info.get("available", []))
                info["available"] = list(msg.interfaces)
                self._scanner_info[msg.scanner] = info
                active = set(info.get("active", []))
                self.interfaces_updated.emit(msg.scanner, list(msg.interfaces), list(active))
                # Auto-activate only newly appeared interfaces, leaving the existing active
                # set untouched so user-configured interface selections are not overridden
                appeared = set(msg.interfaces) - prev_available
                to_add = {i for i in appeared if not i.startswith("lo") and i != "docker0"}
                if to_add - active:
                    client.send_cmd(ClientSetActiveInterfaces(scanner=msg.scanner, interfaces=list(active | to_add)))
            case ServerActiveInterfacesChanged():
                info = self._scanner_info.get(msg.scanner, {})
                info["active"] = list(msg.interfaces)
                self._scanner_info[msg.scanner] = info
                available = info.get("available", [])
                self.interfaces_updated.emit(msg.scanner, list(available), list(msg.interfaces))
            case _:
                pass
