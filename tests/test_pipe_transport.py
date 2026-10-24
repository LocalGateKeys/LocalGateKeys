import pytest

from localvault.pipe_transport import _decode, _encode
from localvault.protocol import ProtocolError


def test_named_pipe_framing_round_trip() -> None:
    payload = {"action": "ping", "value": "ok"}
    assert _decode(_encode(payload)) == payload


def test_named_pipe_framing_rejects_trailing_bytes() -> None:
    with pytest.raises(ProtocolError):
        _decode(_encode({"a": 1}) + b"x")
