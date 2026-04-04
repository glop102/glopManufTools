import json
import logging
from select import select

from .msg_socket import MsgSocket

logger = logging.getLogger("discovery")


class ProtocolClient:
    """
    Synchronous, blocking wrapper over a MsgSocket for use in scanner command loops
    and test drivers. Handles JSON serialisation and provides send/receive helpers
    that hide the raw framing layer.
    """

    def __init__(self, sock: MsgSocket) -> None:
        self._sock = sock

    def send(self, msg: dict) -> None:
        self._sock.send_msg(json.dumps(msg))

    def recv_one(self, timeout: float = 5.0) -> dict:
        """
        Block until one message arrives. Raises RuntimeError on timeout or if the
        server closes the connection without sending a message.
        """
        ready, _, _ = select([self._sock], [], [], timeout)
        if not ready:
            raise RuntimeError(f"Timed out after {timeout}s waiting for a message")
        msgs = self._sock.read_msgs()
        if not msgs:
            raise RuntimeError("Connection closed before a message was received")
        return json.loads(msgs[0])

    def send_and_expect(
        self,
        msg: dict,
        expected_status: str = "accepted",
        timeout: float = 5.0,
    ) -> dict:
        """
        Send a command and assert the immediate response has the expected status.
        Returns the full response dict so callers can inspect extra fields.
        """
        self.send(msg)
        response = self.recv_one(timeout=timeout)
        if response.get("status") != expected_status:
            raise AssertionError(
                f"Expected status {expected_status!r}, got {response.get('status')!r}: {response}"
            )
        return response

    def drain(self, timeout: float = 0.3) -> list[dict]:
        """
        Collect all messages readable within timeout seconds. Used to capture
        fan-out messages that arrive asynchronously after a command is accepted.
        """
        collected: list[dict] = []
        deadline_reached = False
        while not deadline_reached:
            ready, _, _ = select([self._sock], [], [], timeout)
            if not ready:
                deadline_reached = True
                break
            for raw in self._sock.read_msgs():
                collected.append(json.loads(raw))
        return collected
