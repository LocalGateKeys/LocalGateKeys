"""Native-provider control-flow mocks: not real TPM/biometric integration tests."""
import ctypes
from contextlib import contextmanager

import pytest

from localvault.windows_hello import (
    DWORD,
    HANDLE,
    NTE_SILENT_CONTEXT,
    HelloCancelled,
    HelloError,
    HelloUnavailable,
    NativeError,
    WindowsHello,
    validate_record_id,
)


@pytest.fixture
def native(monkeypatch):
    obj = WindowsHello.__new__(WindowsHello)
    props = {"Key Usage": 3, "Export Policy": 0, "Length": 2048, "NgcCacheType": 1}
    obj._get_int = lambda _key, name: props[name]
    return obj, props


def test_policy_accepts_nonexportable_fresh_use_key(native):
    obj, _props = native
    obj._policy(HANDLE(1))


@pytest.mark.parametrize("name,value", [("Key Usage", 0), ("Key Usage", 11),
    ("Export Policy", 1), ("Export Policy", 2), ("Export Policy", 4),
    ("Length", 1024), ("NgcCacheType", 0), ("NgcCacheType", 2)])
def test_policy_rejects_unsafe_key(native, name, value):
    obj, props = native; props[name] = value
    with pytest.raises(HelloError):
        obj._policy(HANDLE(1))


def setup_unwrap(obj):
    @contextmanager
    def key(_record):
        yield HANDLE(1)
    obj._key = key
    obj._context = lambda *_args: None
    obj._set = lambda *_args: None


def test_private_decryption_requires_silent_failure_first(native):
    obj, _ = native; setup_unwrap(obj); calls = []
    def crypt(_key, _data, *, decrypt, silent=False, oaep_hash="SHA256"):
        calls.append((silent, oaep_hash)); assert decrypt
        if silent:
            raise NativeError("decrypt", NTE_SILENT_CONTEXT)
        return bytearray(b"S" * 32)
    obj._crypt = crypt
    assert obj.unwrap("a" * 32, b"c" * 256, 123) == bytearray(b"S" * 32)
    assert calls == [(True, "SHA256"), (False, "SHA256")]
    calls.clear()
    assert obj.unwrap("a" * 32, b"c" * 256, 123, "SHA1") == bytearray(b"S" * 32)
    assert calls == [(True, "SHA1"), (False, "SHA1")]


def test_silent_success_is_wiped_and_never_authorizes(native):
    obj, _ = native; setup_unwrap(obj)
    output = bytearray(b"S" * 32); calls = []
    def crypt(*_args, **kwargs):
        calls.append(kwargs["silent"]); return output
    obj._crypt = crypt
    with pytest.raises(HelloError, match="without fresh verification"):
        obj.unwrap("a" * 32, b"c" * 256, 123)
    assert not any(output) and calls == [True]


def test_unexpected_native_error_is_not_treated_as_authentication(native):
    obj, _ = native; setup_unwrap(obj); calls = []
    def crypt(*_args, **kwargs):
        calls.append(kwargs["silent"]); raise NativeError("decrypt", 0x80090029)
    obj._crypt = crypt
    with pytest.raises(NativeError):
        obj.unwrap("a" * 32, b"c" * 256, 123)
    assert calls == [True]


@pytest.mark.parametrize("code", [0x80090036, 0x800704C7, ctypes.c_int32(0x80090036).value])
def test_cancel_status_codes_fail_closed(code):
    with pytest.raises(HelloCancelled):
        WindowsHello._check(code, "test")


def test_ctypes_layout_sizes_match_windows_abi():
    assert ctypes.sizeof(DWORD) == 4
    assert ctypes.sizeof(HANDLE) == ctypes.sizeof(ctypes.c_void_p)


@pytest.mark.parametrize("record", ["", "../other", "A" * 32, "0" * 31, None, 123])
def test_key_name_input_is_strict(record):
    with pytest.raises(HelloError):
        validate_record_id(record)


def test_policy_fallback_is_not_used_for_permission_errors(native):
    obj, _ = native; calls = []
    def set_prop(_key, name, _value):
        calls.append(name); raise NativeError("policy", 0x80090010)
    obj._set = set_prop
    with pytest.raises(NativeError):
        obj._set_cache(HANDLE(1))
    assert calls == ["NgcCacheType"]


def test_unsupported_current_policy_can_use_legacy_property(native):
    obj, _ = native; calls = []
    def set_prop(_key, name, value):
        calls.append(name); assert value.value == 1
        if name == "NgcCacheType":
            raise NativeError("policy", 0x80090029)
    obj._set = set_prop
    obj._set_cache(HANDLE(1))
    assert calls == ["NgcCacheType", "NgcCacheTypeProperty"]


def test_absent_native_policy_never_downgrades(native):
    obj, _ = native
    def set_prop(*_args):
        raise NativeError("policy", 0x80090029)
    obj._set = set_prop
    with pytest.raises(HelloUnavailable):
        obj._set_cache(HANDLE(1))


def test_native_prompt_requires_a_parent(native):
    obj, _ = native
    with pytest.raises(HelloError, match="visible"):
        obj._context(HANDLE(1), 0, "Unlock")
