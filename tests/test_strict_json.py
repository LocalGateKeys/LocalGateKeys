from __future__ import annotations

import time

import pytest

from localvault.strict_json import MAX_DEPTH, strict_loads


def test_depth_limit_is_enforced():
    strict_loads(("[" * MAX_DEPTH + "]" * MAX_DEPTH).encode())
    with pytest.raises(ValueError):
        strict_loads(("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)).encode())


def test_brackets_in_strings_and_escaped_quotes_are_ignored():
    text = '{"a": "' + "[" * 2000 + '", "b": "x\\"' + "{" * 2000 + '\\\\", "c": [1]}'
    assert strict_loads(text.encode())["c"] == [1]
    with pytest.raises(ValueError):
        strict_loads((('{"k": "]\\"",' * 600).encode() + b'"z":' + b"[" * 1 + b"]" + b"}" * 600))


def test_deep_object_after_strings_is_still_refused():
    text = '{"s":"}}}"' + ',"n":' + '{"x":' * (MAX_DEPTH + 1) + "1" + "}" * (MAX_DEPTH + 1) + "}"
    with pytest.raises(ValueError, match="deeply"):
        strict_loads(text.encode())


def test_flat_ten_megabytes_is_checked_quickly():
    body = ('{"k":"' + "a" * 90 + '"},') * 105_000
    data = ("[" + body + "1]").encode()
    assert len(data) > 10_000_000
    start = time.perf_counter()
    from localvault.strict_json import _check_depth
    _check_depth(data.decode())
    assert time.perf_counter() - start < 1.0
