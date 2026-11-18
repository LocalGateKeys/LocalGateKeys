"""Strict JSON loading that matches the Swift and Kotlin canonical parsers.

Rejects duplicate keys, NaN/Infinity, floats that overflow (1e400), integers beyond 64 bits (including Int64.min)
and lone surrogate escapes (every string and key must encode to UTF-8).
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

_MAX_JSON_INT = 2**63 - 1
MAX_DEPTH = 512  # the phones' canonical parsers stop here


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _parse_int(text: str) -> int:
    value = int(text)
    if abs(value) > _MAX_JSON_INT:  # also refuses Int64.min, as the phones do
        raise ValueError("integer beyond 64 bits")
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    return value


def _check_text(value: Any) -> None:
    if isinstance(value, str):
        value.encode("utf-8")  # a lone surrogate raises UnicodeEncodeError (a ValueError)
    elif isinstance(value, list):
        for item in value:
            _check_text(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_text(key)
            _check_text(item)


_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_BRACKET = re.compile(r"[\[\]{}]")


def _check_depth(text: str) -> None:
    """Refuse nesting deeper than MAX_DEPTH before parsing, so the parser never recurses far.

    String literals are removed with one regex, then only the bracket characters are walked (fast on big files).
    """
    depth = 0
    for match in _BRACKET.finditer(_STRING.sub('""', text)):
        if match.group() in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON nested too deeply")
        else:
            depth -= 1


def strict_loads(data: bytes) -> Any:
    """Parse UTF-8 JSON bytes; raises ValueError (or a subclass) for anything the phones refuse."""
    text = data.decode("utf-8")
    _check_depth(text)
    value = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                       parse_constant=_reject_constant, parse_int=_parse_int, parse_float=_parse_float)
    _check_text(value)
    return value
