from __future__ import annotations

import json
import socket
import struct
import sys
from typing import Any, BinaryIO

MAX_NATIVE_INBOUND = 64 * 1024
MAX_NATIVE_OUTBOUND = 1024 * 1024
MAX_LOCAL_MESSAGE = 1024 * 1024


class ProtocolError(Exception):
    pass


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("Unexpected end of stream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_native_message(stream: BinaryIO) -> dict[str, Any] | None:
    header = stream.read(4)
    if header == b"":
        return None
    if len(header) != 4:
        raise ProtocolError("Truncated native messaging header")
    (length,) = struct.unpack("=I", header)
    if length > MAX_NATIVE_INBOUND:
        raise ProtocolError("Native message exceeds the inbound limit")
    payload = _read_exact(stream, length)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Invalid native messaging JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("Native message must be a JSON object")
    return value


def write_native_message(stream: BinaryIO, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_NATIVE_OUTBOUND:
        raise ProtocolError("Native response exceeds Chrome's 1 MiB limit")
    stream.write(struct.pack("=I", len(payload)))
    stream.write(payload)
    stream.flush()


def configure_windows_binary_stdio() -> None:
    if sys.platform != "win32":
        return
    import msvcrt  # type: ignore[import-not-found]

    msvcrt.setmode(sys.stdin.fileno(), 0x8000)  # os.O_BINARY
    msvcrt.setmode(sys.stdout.fileno(), 0x8000)


def send_local_message(sock: socket.socket, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_LOCAL_MESSAGE:
        raise ProtocolError("Local agent message is too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_local_message(sock: socket.socket) -> dict[str, Any]:
    header = _recv_exact_socket(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length > MAX_LOCAL_MESSAGE:
        raise ProtocolError("Local agent message is too large")
    payload = _recv_exact_socket(sock, length)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Invalid local agent JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("Local message must be a JSON object")
    return value


def _recv_exact_socket(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("Unexpected end of socket")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
