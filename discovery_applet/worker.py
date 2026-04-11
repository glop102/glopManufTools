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

logger = logging.getLogger("discovery_applet.worker")

_STARTUP_TIMEOUT = 5.0  # seconds to wait for mdns.v1 to appear


class DiscoveryWorker(QThread):
    hosts_updated = pyqtSignal(str, dict)   # key, MDNSHostData-dict
    hosts_removed = pyqtSignal(list)        # list[str] of keys
    status_changed = pyqtSignal(str)        # "connecting" | "connected" | "error: ..."

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cmd_queue: queue.SimpleQueue[dict] = queue.SimpleQueue()
        self._active_scanners: list[str] = []

    def stop_all_scanners(self) -> None:
        """Thread-safe: request that all known scanners be stopped."""
        for scanner in list(self._active_scanners):
            self._cmd_queue.put({"command": "stop_scanner", "scanner": scanner})

    def start_mdns_scanner(self) -> None:
        """Thread-safe: request that mdns.v1 be started (no-op if already running)."""
        self._cmd_queue.put({"command": "_start_mdns"})

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
        """Return the next buffered message, refilling from the socket if needed."""
        if not self._buf:
            self._fill_buf(client, timeout)
        return self._buf.popleft()

    def _setup(self, client) -> None:
        """Announce, ensure mdns.v1 is running, activate interfaces, seed UI."""
        # 1. Announce
        client.send_msg({"command": "announce", "type": "client"})
        resp = self._recv(client)
        current_scanners: list[str] = resp.get("scanners", [])
        self._active_scanners = list(current_scanners)

        # 2. Start mdns.v1 if not already running
        if "mdns.v1" not in current_scanners:
            client.send_msg({"command": "start_builtin_scanner", "scanner": "mdns.v1"})
            start_resp = self._recv(client)
            if start_resp.get("status") != "accepted":
                raise RuntimeError(f"start_builtin_scanner rejected: {start_resp}")
            if not self._wait_for_scanner(client, "mdns.v1"):
                raise RuntimeError("mdns.v1 did not start within timeout")
            self._active_scanners.append("mdns.v1")

        # 3. Get available interfaces and activate non-loopback ones
        client.send_msg({"command": "get_registered_scanner", "scanner": "mdns.v1"})
        scanner_info = self._recv(client)
        available: list[str] = scanner_info.get("available_interfaces", [])
        active = [iface for iface in available if not iface.startswith("lo")]

        if active:
            client.send_msg({
                "command": "set_active_interfaces",
                "scanner": "mdns.v1",
                "interfaces": active,
            })
            self._recv(client)  # consume status: accepted

        # 4. Seed UI with any results already known to the server
        client.send_msg({"command": "get_results", "scanner": "mdns.v1"})
        results_resp = self._recv(client)
        for entry in results_resp.get("results", []):
            self.hosts_updated.emit(entry["key"], entry["result"])

        self.status_changed.emit("connected")

    def _wait_for_scanner(self, client, scanner_name: str) -> bool:
        """
        Drain messages until available_scanners_changed includes scanner_name,
        or the timeout elapses. Returns True if found.
        """
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            # Drain any already-buffered messages first
            while self._buf:
                msg = self._buf.popleft()
                if (
                    msg.get("command") == "available_scanners_changed"
                    and scanner_name in msg.get("scanners", [])
                ):
                    return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._fill_buf(client, timeout=min(remaining, 0.5))
            except RuntimeError:
                pass  # timeout on this iteration is fine, keep looping
        return False

    def _do_start_mdns(self, client) -> None:
        """Start mdns.v1, activate interfaces, and seed UI with existing results."""
        if "mdns.v1" in self._active_scanners:
            logger.info("mdns.v1 is already running, ignoring start request")
            return

        logger.info("Starting mdns.v1 scanner")
        client.send_msg({"command": "start_builtin_scanner", "scanner": "mdns.v1"})
        start_resp = self._recv(client)
        if start_resp.get("status") != "accepted":
            logger.error("start_builtin_scanner rejected: %s", start_resp)
            self.status_changed.emit("error: mdns.v1 start rejected")
            return

        if not self._wait_for_scanner(client, "mdns.v1"):
            logger.error("mdns.v1 did not start within timeout")
            self.status_changed.emit("error: mdns.v1 start timed out")
            return

        self._active_scanners.append("mdns.v1")

        client.send_msg({"command": "get_registered_scanner", "scanner": "mdns.v1"})
        scanner_info = self._recv(client)
        available: list[str] = scanner_info.get("available_interfaces", [])
        active = [iface for iface in available if not iface.startswith("lo")]
        if active:
            client.send_msg({
                "command": "set_active_interfaces",
                "scanner": "mdns.v1",
                "interfaces": active,
            })
            self._recv(client)  # consume status: accepted

        client.send_msg({"command": "get_results", "scanner": "mdns.v1"})
        results_resp = self._recv(client)
        for entry in results_resp.get("results", []):
            self.hosts_updated.emit(entry["key"], entry["result"])

        self.status_changed.emit("connected")

    def _loop(self, client) -> None:
        """Main event loop — forwards scan results to the UI thread via signals."""
        while not self.isInterruptionRequested():
            # Drain any commands queued from the main thread
            while not self._cmd_queue.empty():
                try:
                    cmd = self._cmd_queue.get_nowait()
                except queue.Empty:
                    break
                if cmd["command"] == "_start_mdns":
                    self._do_start_mdns(client)
                else:
                    client.send_msg(cmd)
                    self._recv(client, timeout=2.0)  # consume the status reply

            # Process any messages already in the buffer before blocking on select
            while self._buf:
                self._handle_msg(client, self._buf.popleft())

            ready, _, _ = select([client], [], [], 0.5)
            if not ready:
                continue

            try:
                msgs = client.read_msgs()
            except ConnectionError:
                logger.info("Server connection closed")
                self.status_changed.emit("error: server disconnected")
                break

            for msg in msgs:
                self._handle_msg(client, msg)

    def _handle_msg(self, client, msg: dict) -> None:
        match msg.get("command"):
            case "scan_results_update":
                for entry in msg.get("results", []):
                    self.hosts_updated.emit(entry["key"], entry["result"])
            case "scan_results_remove":
                keys = msg.get("keys", [])
                if keys:
                    self.hosts_removed.emit(keys)
            case "available_interfaces_changed":
                available: list[str] = msg.get("interfaces", [])
                active = [i for i in available if not i.startswith("lo")]
                if active:
                    client.send_msg({
                        "command": "set_active_interfaces",
                        "scanner": "mdns.v1",
                        "interfaces": active,
                    })
            case _:
                pass
