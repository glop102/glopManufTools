import logging
import socket
import struct
from select import select

logger = logging.getLogger("discovery")

class MsgSocket:
    """
    Wrapper around a connected stream socket that frames messages with a 4-byte
    big-endian length header followed by the UTF-8 encoded message body.

    Supports being passed directly to select() via fileno().
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = b""

    def fileno(self) -> int:
        """Allow select() to use this object directly."""
        return self._sock.fileno()

    def read_msgs(self) -> list[str]:
        """
        Reads all the queued bytes into our buffer and then parses out messages.
        This accounts for clients trying to send multiple messages at once and
        also clients sending messages in chunks.
        """
        # While the socket is readable, drain its buffer
        while len(select([self._sock],[],[],0.0)[0]):
            # Try to read from the buffer from the socket
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Socket Closed when retrieving buffer for messages")
            self._buf += chunk

        # Now that we have fully drained the socket's buffer, lets try to parse out any messages that have been sent
        # We parse the header to know the size, then if there are enough bytes in the buffer, we mutate the buffer
        # and add it to the list of messages
        messages_found:list[str] = []
        while len(self._buf) >= 4:
            (msg_len,) = struct.unpack(">I", self._buf[:4])
            if len(self._buf) >= msg_len+4:
                msg = self._buf[4:4+msg_len]
                self._buf = self._buf[4+msg_len:]
                try:
                    messages_found.append(msg.decode("utf-8"))
                except UnicodeDecodeError as e:
                    logger.error(f"Unable to decode buffered message: len({msg_len})",exc_info=e)
            else:
                # The message is not fully buffered yet
                break
        return messages_found

    def send_msg(self, msg: str) -> None:
        """
        Send a message framed with a 4-byte big-endian length header.
        """
        data = msg.encode("utf-8")
        header = struct.pack(">I", len(data))
        self._sock.sendall(header + data)
