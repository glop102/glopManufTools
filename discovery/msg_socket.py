import json
import logging
import socket
import struct
from select import select
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import BaseModel

logger = logging.getLogger("discovery")


class MsgSocket:
    """
    Wrapper around a connected stream socket that frames messages with a 4-byte
    big-endian length header followed by the UTF-8 encoded message body.

    Supports being passed directly to select() via fileno().
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._sock.setblocking(False)
        self._read_buf = b""
        self._write_buf = b""

    def fileno(self) -> int:
        """Allow select() to use this object directly."""
        return self._sock.fileno()

    def read_msgs(self) -> list[dict]:
        """
        Reads all the queued bytes into our buffer, parses out framed messages,
        and JSON-decodes each one. Messages that fail to decode are logged and
        skipped. This accounts for clients trying to send multiple messages at
        once and also clients sending messages in chunks.
        """
        # While the socket is readable, drain its buffer
        while len(select([self._sock], [], [], 0.0)[0]):
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError(
                    "Socket Closed when retrieving buffer for messages"
                )
            self._read_buf += chunk

        messages_found: list[dict] = []
        while len(self._read_buf) >= 4:
            (msg_len,) = struct.unpack(">I", self._read_buf[:4])
            if len(self._read_buf) >= msg_len + 4:
                raw = self._read_buf[4 : 4 + msg_len]
                self._read_buf = self._read_buf[4 + msg_len :]
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                    if not isinstance(decoded, dict):
                        raise ValueError(f"Expected a JSON object, got {type(decoded).__name__}")
                    messages_found.append(decoded)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
                    logger.error(
                        f"Unable to decode buffered message: len({msg_len})", exc_info=e
                    )
            else:
                # The message is not fully buffered yet
                break
        return messages_found

    def msg_data_write_queued(self) -> bool:
        return len(self._write_buf) > 0

    def send_cmd(self, model: "BaseModel", *, send_synchronous: bool = True) -> None:
        """Send a pydantic command model, serialised to JSON with None fields omitted."""
        self.send_msg(model.model_dump(exclude_none=True), send_synchronous=send_synchronous)

    def send_msg(self, msg: str | dict, send_synchronous: bool = True) -> None:
        """
        Send a message framed with a 4-byte big-endian length header.
        msg may be a str or a dict; dicts are serialised to JSON automatically.
        When send_synchronous is True (default), blocks until all queued bytes
        have been sent.
        When False, queues the bytes and flushes as much as possible without
        blocking, leaving any remainder for the next flush_write_buf() call.
        """
        if isinstance(msg, dict):
            msg = json.dumps(msg)
        data = msg.encode("utf-8")
        self._write_buf += struct.pack(">I", len(data)) + data
        if send_synchronous:
            self._flush_sync()
        else:
            self.flush_write_buf()

    def _flush_sync(self) -> None:
        """
        Block until every queued byte has been sent.
        Uses select() to wait for writability so the socket can stay non-blocking
        and the non-blocking async path in flush_write_buf() keeps working correctly.
        """
        while self._write_buf:
            _, writable, _ = select([], [self._sock], [], None)
            if not writable:
                continue
            try:
                sent = self._sock.send(self._write_buf)
                self._write_buf = self._write_buf[sent:]
            except BlockingIOError:
                pass
            except OSError as e:
                raise ConnectionError("Socket write failed") from e

    def close(self) -> None:
        self._sock.close()

    def flush_write_buf(self) -> None:
        """
        Write as many queued bytes to the socket as possible without blocking.
        Any bytes that could not be sent remain in the buffer for the next flush.
        """
        if not self._write_buf:
            return
        try:
            sent = self._sock.send(self._write_buf)
            self._write_buf = self._write_buf[sent:]
        except BlockingIOError:
            pass
        except OSError as e:
            raise ConnectionError("Socket write failed") from e
