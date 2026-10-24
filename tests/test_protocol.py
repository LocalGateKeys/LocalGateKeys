import io
import socket

from localvault.protocol import (
    read_native_message,
    recv_local_message,
    send_local_message,
    write_native_message,
)


def test_native_message_round_trip() -> None:
    stream = io.BytesIO()
    write_native_message(stream, {"ok": True, "text": "zażółć"})
    stream.seek(0)
    assert read_native_message(stream) == {"ok": True, "text": "zażółć"}


def test_native_eof() -> None:
    assert read_native_message(io.BytesIO()) is None


def test_local_socket_round_trip() -> None:
    left, right = socket.socketpair()
    try:
        send_local_message(left, {"action": "ping"})
        assert recv_local_message(right) == {"action": "ping"}
    finally:
        left.close()
        right.close()


def test_native_message_rejects_oversized_input() -> None:
    import struct

    from localvault.protocol import MAX_NATIVE_INBOUND, ProtocolError

    stream = io.BytesIO(struct.pack("=I", MAX_NATIVE_INBOUND + 1))
    try:
        read_native_message(stream)
    except ProtocolError as exc:
        assert "exceeds" in str(exc)
    else:
        raise AssertionError("Oversized native message was accepted")
