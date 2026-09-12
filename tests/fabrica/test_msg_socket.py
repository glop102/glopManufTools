"""
Tests for discovery/msg_socket.py

Covers the read-side error translation: every failure mode of recv() must
surface as ConnectionError so the server's single except clause drops the peer
instead of crashing.
"""

import errno
import socket

import pytest

from fabrica.discovery.msg_socket import MsgSocket


class _FailingRecv:
    """Stand-in for a socket whose recv() fails with a plain OSError.

    fileno() is backed by a real readable descriptor so select() reports it ready.
    """

    def __init__(self, real: socket.socket, exc: BaseException):
        self._real = real
        self._exc = exc

    def fileno(self) -> int:
        return self._real.fileno()

    def setblocking(self, flag: bool) -> None:
        self._real.setblocking(flag)

    def recv(self, _n: int) -> bytes:
        raise self._exc

    def close(self) -> None:
        self._real.close()


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_plain_oserror_on_recv_becomes_connection_error(pair):
    a, b = pair
    b.sendall(b"x")  # make `a` readable so read_msgs reaches recv()
    ms = MsgSocket(_FailingRecv(a, OSError(errno.ETIMEDOUT, "Connection timed out")))
    with pytest.raises(ConnectionError):
        ms.read_msgs()


def test_blocking_io_error_is_not_a_failure(pair):
    a, b = pair
    b.sendall(b"x")
    ms = MsgSocket(_FailingRecv(a, BlockingIOError(errno.EAGAIN, "try again")))
    assert ms.read_msgs() == []


def test_read_after_close_raises_connection_error(pair):
    a, _b = pair
    ms = MsgSocket(a)
    ms.close()
    with pytest.raises(ConnectionError):
        ms.read_msgs()


def test_peer_close_raises_connection_error(pair):
    a, b = pair
    ms = MsgSocket(a)
    b.close()
    with pytest.raises(ConnectionError):
        ms.read_msgs()
