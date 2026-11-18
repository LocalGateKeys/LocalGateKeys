"""SSH agent message codec (draft-miller-ssh-agent): framing, the supported messages and session-bind."""
from __future__ import annotations

import struct

import pytest

from localvault.ssh_agent import protocol as p
from localvault.ssh_keys import ssh_string


def _frame(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def test_roundtrip_each_message():
    bind = p.SessionBind(host_key=b"hk", session_id=b"sid", signature=b"sig", forwarding=True)
    messages = [
        p.AgentMessage(p.REQUEST_IDENTITIES),
        p.AgentMessage(p.IDENTITIES_ANSWER, identities=((b"blob1", "first"), (b"blob2", "second ü"))),
        p.AgentMessage(p.IDENTITIES_ANSWER),
        p.AgentMessage(p.SIGN_REQUEST, key_blob=b"blob", data=b"to sign", flags=4),
        p.AgentMessage(p.SIGN_RESPONSE, signature=b"signature"),
        p.AgentMessage(p.SUCCESS),
        p.AgentMessage(p.FAILURE),
        p.AgentMessage(p.EXTENSION, extension=p.SESSION_BIND, bind=bind),
        p.AgentMessage(p.EXTENSION, extension="query", contents=b"raw"),
    ]
    for message in messages:
        assert p.decode(p.encode(message)) == message


def test_wire_layout_matches_the_draft():
    assert p.encode(p.AgentMessage(p.FAILURE)) == b"\x00\x00\x00\x01\x05"
    answer = p.encode(p.AgentMessage(p.IDENTITIES_ANSWER, identities=((b"k", "c"),)))
    assert answer == _frame(b"\x0c" + struct.pack(">I", 1) + ssh_string(b"k") + ssh_string(b"c"))
    request = _frame(b"\x0d" + ssh_string(b"k") + ssh_string(b"d") + struct.pack(">I", 2))
    assert p.decode(request) == p.AgentMessage(p.SIGN_REQUEST, key_blob=b"k", data=b"d", flags=2)


def test_unknown_type_failure():
    # ADD_IDENTITY (17), REMOVE_ALL (19), LOCK (22)...: decoded as "unknown", which the server answers with FAILURE.
    for kind in (17, 19, 22, 25, 200):
        message = p.decode(_frame(bytes([kind]) + b"whatever"))
        assert message.type == kind
        assert p.reply_for_unsupported(message) == p.AgentMessage(p.FAILURE)
    assert p.reply_for_unsupported(p.AgentMessage(p.EXTENSION, extension="query")) == p.AgentMessage(p.FAILURE)


def test_oversize_frame_closes():
    assert p.MAX_FRAME == 256 * 1024
    with pytest.raises(p.AgentProtocolError):
        p.check_length(struct.pack(">I", p.MAX_FRAME + 1))
    with pytest.raises(p.AgentProtocolError):
        p.check_length(struct.pack(">I", 0))
    assert p.check_length(struct.pack(">I", p.MAX_FRAME)) == p.MAX_FRAME
    with pytest.raises(p.AgentProtocolError):
        p.decode(struct.pack(">I", p.MAX_FRAME + 1) + b"\x0b" * (p.MAX_FRAME + 1))


def test_truncated_frame_closes():
    with pytest.raises(p.AgentProtocolError):
        p.decode(b"\x00\x00")  # short header
    with pytest.raises(p.AgentProtocolError):
        p.decode(b"\x00\x00\x00\x05\x0b")  # declared 5, got 1
    with pytest.raises(p.AgentProtocolError):
        p.decode(_frame(b"\x0d" + struct.pack(">I", 99) + b"short"))  # string runs past the end
    with pytest.raises(p.AgentProtocolError):
        p.decode(_frame(b"\x0d" + ssh_string(b"k") + ssh_string(b"d")))  # flags missing
    with pytest.raises(p.AgentProtocolError):
        p.decode(_frame(b"\x1b" + ssh_string(p.SESSION_BIND.encode()) + ssh_string(b"hk")))


def test_session_bind_parsed():
    body = (b"\x1b" + ssh_string(b"session-bind@openssh.com") + ssh_string(b"HOSTKEY") + ssh_string(b"SESSION")
            + ssh_string(b"SIG") + b"\x00")
    message = p.decode(_frame(body))
    assert message.type == p.EXTENSION and message.extension == p.SESSION_BIND
    assert message.bind == p.SessionBind(b"HOSTKEY", b"SESSION", b"SIG", False)
    forwarded = p.decode(_frame(body[:-1] + b"\x01"))
    assert forwarded.bind.forwarding is True
