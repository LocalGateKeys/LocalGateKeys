"""Property tests for the length-prefixed frame codecs.

Targets: protocol.read_native_message / recv_local_message, native_host._read_native_message,
pipe_transport._decode / _recv_pipe / _read_exact_pipe (through a fake ``win32file``),
sync.transport.decode_frame / SyncTransport._read_socket_frame.

Each reader is fed a stream that returns random short reads and records every read
size, so "never asks for (allocates) more than the bound" is checked directly.
"""
from __future__ import annotations

import json
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from localvault import native_host, pipe_transport, protocol
from localvault.protocol import ProtocolError
from localvault.sync import transport as T


class ChunkedStream:
    """A file-like/socket-like object: random short reads, every request recorded."""

    def __init__(self, data: bytes, chunks: list[int]):
        self.data, self.pos, self.chunks, self.requests = data, 0, list(chunks), []

    def _take(self, n: int) -> bytes:
        self.requests.append(n)
        step = self.chunks.pop(0) if self.chunks else n
        step = max(1, min(n, step))
        out = self.data[self.pos:self.pos + step]
        self.pos += len(out)
        return out

    read = _take
    recv = _take

    def settimeout(self, _t):
        pass


json_value = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=30)),
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=8), inner, max_size=4)),
    max_leaves=20)
payload = st.one_of(
    json_value.map(lambda v: json.dumps(v).encode()),
    st.dictionaries(st.text(max_size=8), json_value, max_size=5).map(lambda v: json.dumps(v, ensure_ascii=False).encode()),
    st.binary(max_size=200),
    st.sampled_from([b'{"a":"\\ud800"}', b"{\"a\":NaN}", b'{"a":1,"a":2}', b"\xef\xbb\xbf{}", b"{}\x00",
                     b"[" * 500, b'{"a":"\xed\xa0\x80"}', b"1e999999"]),
)
length_field = st.one_of(st.none(), st.integers(0, 2**32 - 1),
                         st.sampled_from([0, 1, 2**16, 2**16 + 1, 2**20, 2**20 + 1, 2**31, 2**32 - 1]))
chunks = st.lists(st.integers(1, 64), max_size=40)


def _frame(body: bytes, length: int | None, fmt: str) -> bytes:
    return struct.pack(fmt, len(body) if length is None else length) + body


def _check_reader(read, data, chunk_list, bound, allowed):
    stream = ChunkedStream(data, chunk_list)
    try:
        result = read(stream)
    except allowed:
        result = None
    assert all(n <= bound for n in stream.requests), f"read request above bound: {max(stream.requests)}"
    assert stream.pos <= bound + 4
    return result


# ------------------------------------------------------------- native messaging (browser -> host)
@given(payload, length_field, chunks, st.binary(max_size=8))
def test_protocol_read_native_message(body, length, chunk_list, tail):
    result = _check_reader(protocol.read_native_message, _frame(body, length, "=I") + tail, chunk_list,
                           protocol.MAX_NATIVE_INBOUND, (ProtocolError, EOFError))
    assert result is None or isinstance(result, dict)


@given(payload, length_field, chunks, st.binary(max_size=8))
def test_native_host_read_native_message(body, length, chunk_list, tail):
    result = _check_reader(native_host._read_native_message, _frame(body, length, "=I") + tail, chunk_list,
                           native_host._MAX_NATIVE_MESSAGE, (native_host.NativeBridgeError, EOFError))
    assert result is None or isinstance(result, dict)


@given(st.binary(max_size=3), chunks)
def test_native_truncated_header(header, chunk_list):
    for read, errors in ((protocol.read_native_message, (ProtocolError, EOFError)),
                         (native_host._read_native_message, (native_host.NativeBridgeError, EOFError))):
        stream = ChunkedStream(header, [len(header) or 1])
        try:
            assert read(stream) is None and header == b""
        except errors:
            pass


# ------------------------------------------------------------- local socket (protocol.recv_local_message)
@given(payload, length_field, chunks)
def test_protocol_recv_local_message(body, length, chunk_list):
    result = _check_reader(protocol.recv_local_message, _frame(body, length, "!I"), chunk_list,
                           protocol.MAX_LOCAL_MESSAGE, (ProtocolError, EOFError))
    assert result is None or isinstance(result, dict)


# ------------------------------------------------------------- named pipe
@given(payload, length_field, st.binary(max_size=8))
def test_pipe_decode_only_protocol_error(body, length, tail):
    try:
        value = pipe_transport._decode(_frame(body, length, "!I") + tail)
    except ProtocolError:
        return
    assert isinstance(value, dict)
    # Anything accepted must re-encode (the reply path relies on it).
    pipe_transport._encode(value)


@given(st.dictionaries(st.text(max_size=10), json_value, max_size=6))
def test_pipe_round_trip(value):
    try:
        blob = pipe_transport._encode(value)
    except ProtocolError:
        return
    assert pipe_transport._decode(blob) == value or json.dumps(value) == json.dumps(pipe_transport._decode(blob))


@pytest.fixture
def fake_win32file(monkeypatch):
    win32file = pytest.importorskip("win32file")

    def read_file(handle, n):
        return 0, handle.read(n)

    monkeypatch.setattr(win32file, "ReadFile", read_file)
    return win32file


@given(payload, length_field, chunks)
def test_recv_pipe_bounded(fake_win32file, body, length, chunk_list):
    result = _check_reader(pipe_transport._recv_pipe, _frame(body, length, "!I"), chunk_list,
                           protocol.MAX_LOCAL_MESSAGE, (ProtocolError, EOFError))
    assert result is None or isinstance(result, dict)


# ------------------------------------------------------------- sync transport frames
@given(st.binary(max_size=64), length_field, st.binary(max_size=4))
def test_sync_decode_frame(body, length, tail):
    frame = _frame(body, length, ">I") + tail
    try:
        out = T.decode_frame(frame)
    except T.TransportError:
        return
    assert T.encode_frame(out) == frame


@given(st.binary(max_size=64), length_field, chunks, st.integers(1, T.MAX_FRAME_PAYLOAD))
def test_sync_read_socket_frame(body, length, chunk_list, limit):
    transport = T.SyncTransport()
    import time
    raw = _frame(body, length, ">I")
    stream = ChunkedStream(raw, chunk_list)
    try:
        frame = transport._read_socket_frame(stream, time.monotonic() + 5, limit)
    except T.TransportError:
        frame = None
    assert all(n <= max(4, min(limit, T.MAX_FRAME_PAYLOAD)) for n in stream.requests)
    if frame is not None:
        declared = struct.unpack(">I", raw[:4])[0]
        assert 1 <= declared <= limit and frame == raw[:4 + declared]
        assert T.decode_frame(frame) == raw[4:4 + declared]


# ------------------------------------------------------------- finding F-1 reproducers
@pytest.mark.parametrize("reader,errors", [
    (protocol.read_native_message, (ProtocolError, EOFError)),
    (native_host._read_native_message, (native_host.NativeBridgeError, EOFError)),
])
def test_deep_json_is_a_protocol_error(reader, errors):
    import io
    body = b"[" * 60000
    with pytest.raises(errors):
        reader(io.BytesIO(struct.pack("=I", len(body)) + body))
