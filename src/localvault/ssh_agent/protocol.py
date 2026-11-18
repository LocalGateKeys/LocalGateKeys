"""SSH agent message codec (draft-miller-ssh-agent).

A frame is ``uint32 length || byte type || contents``. The agent serves REQUEST_IDENTITIES, SIGN_REQUEST and the
``session-bind@openssh.com`` extension; every other request is decoded as an "unknown" message that the server
answers with FAILURE. Any framing or parse error raises :class:`AgentProtocolError`, and the server closes the
connection without a reply. Error messages never carry message bytes.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ..ssh_keys import ssh_string

FAILURE = 5
SUCCESS = 6
REQUEST_IDENTITIES = 11
IDENTITIES_ANSWER = 12
SIGN_REQUEST = 13
SIGN_RESPONSE = 14
EXTENSION = 27
SESSION_BIND = "session-bind@openssh.com"
MAX_FRAME = 256 * 1024
MAX_IDENTITIES = 1024


class AgentProtocolError(Exception):
    """A frame that cannot be read; the connection is closed."""


@dataclass(frozen=True)
class SessionBind:
    host_key: bytes
    session_id: bytes
    signature: bytes
    forwarding: bool


@dataclass(frozen=True)
class AgentMessage:
    type: int
    identities: tuple[tuple[bytes, str], ...] = ()
    key_blob: bytes = b""
    data: bytes = b""
    flags: int = 0
    signature: bytes = b""
    extension: str = ""
    contents: bytes = b""
    bind: SessionBind | None = None


class _Reader:
    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._pos = 0

    def take(self, count: int) -> bytes:
        end = self._pos + count
        if end > len(self._buf):
            raise AgentProtocolError("truncated message")
        value = self._buf[self._pos:end]
        self._pos = end
        return value

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def boolean(self) -> bool:
        return self.take(1) != b"\x00"

    def rest(self) -> bytes:
        value = self._buf[self._pos:]
        self._pos = len(self._buf)
        return value


def check_length(header: bytes) -> int:
    """The body length a 4-byte frame header announces; oversize or empty frames close the connection."""
    if len(header) != 4:
        raise AgentProtocolError("truncated header")
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME:
        raise AgentProtocolError("frame length out of range")
    return length


def decode(frame: bytes) -> AgentMessage:
    """Decode one whole frame (header included). Trailing bytes inside a known message are ignored, as OpenSSH does."""
    length = check_length(frame[:4])
    if len(frame) != 4 + length:
        raise AgentProtocolError("frame length mismatch")
    kind = frame[4]
    body = _Reader(frame[5:])
    if kind == SIGN_REQUEST:
        return AgentMessage(kind, key_blob=body.string(), data=body.string(), flags=body.u32())
    if kind == IDENTITIES_ANSWER:
        count = body.u32()
        if count > MAX_IDENTITIES:
            raise AgentProtocolError("too many identities")
        identities = tuple((body.string(), body.string().decode("utf-8", "replace")) for _ in range(count))
        return AgentMessage(kind, identities=identities)
    if kind == SIGN_RESPONSE:
        return AgentMessage(kind, signature=body.string())
    if kind == EXTENSION:
        name = body.string().decode("utf-8", "replace")
        if name == SESSION_BIND:
            bind = SessionBind(body.string(), body.string(), body.string(), body.boolean())
            return AgentMessage(kind, extension=name, bind=bind)
        return AgentMessage(kind, extension=name, contents=body.rest())
    return AgentMessage(kind)  # REQUEST_IDENTITIES, SUCCESS, FAILURE and every unsupported request


def encode(message: AgentMessage) -> bytes:
    kind = message.type
    if kind == IDENTITIES_ANSWER:
        body = struct.pack(">I", len(message.identities)) + b"".join(
            ssh_string(blob) + ssh_string(comment.encode("utf-8")) for blob, comment in message.identities)
    elif kind == SIGN_REQUEST:
        body = ssh_string(message.key_blob) + ssh_string(message.data) + struct.pack(">I", message.flags)
    elif kind == SIGN_RESPONSE:
        body = ssh_string(message.signature)
    elif kind == EXTENSION:
        body = ssh_string(message.extension.encode("utf-8"))
        if message.bind is not None:
            bind = message.bind
            body += (ssh_string(bind.host_key) + ssh_string(bind.session_id) + ssh_string(bind.signature)
                     + (b"\x01" if bind.forwarding else b"\x00"))
        else:
            body += message.contents
    else:
        body = b""
    payload = bytes([kind]) + body
    if len(payload) > MAX_FRAME:
        raise AgentProtocolError("frame too large")
    return struct.pack(">I", len(payload)) + payload


def reply_for_unsupported(_message: AgentMessage) -> AgentMessage:
    """ADD/REMOVE identity, LOCK, smartcard, other extensions...: always FAILURE."""
    return AgentMessage(FAILURE)
