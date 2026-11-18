"""Local Windows Hello key protection, not a camera-presence/boolean check.

Only the Windows Passport CNG provider is accepted. The provider performs the
private-key operation; LocalGateKeys never receives a face image, template or PIN.
There is deliberately no alternate software-provider/DPAPI-only fallback.

Passport's per-use policy properties are provider-specific (not a stable public
Win32 contract). Unsupported properties, silent decryption, exportable/importable
keys and provider failures all disable this route rather than weaken it. Windows
hardware/Hello integration must also be tested on the target PC. This module does
not attest TPM residency or force face-only verification.
"""
from __future__ import annotations

import ctypes as ct
import re
import struct
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .i18n import t

PROVIDER = "Microsoft Passport Key Storage Provider"
RSA_BITS = 2048
RSA_BYTES = RSA_BITS // 8
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_PAD_OAEP_FLAG = 0x04
NTE_SILENT_CONTEXT = 0x80090022
MISSING_KEY_CODES = {0x8009000D, 0x80090016}
CANCEL_CODES = {0x80090036, 0x800704C7}
NTE_INVALID_PARAMETER = 0x80090027
# Some Passport providers (for example TPM 1.2 backed keys) refuse OAEP with
# SHA-256 as an invalid parameter; OAEP with SHA-1 is still sound for wrapping
# a random 32-byte secret.
# "PKCS1" is the last resort for providers that refuse OAEP outright. It only wraps a
# random 32-byte secret, and every private-key use needs a fresh Hello gesture, so a
# padding oracle cannot be driven at any useful rate.
OAEP_HASHES = ("SHA256", "SHA1", "PKCS1")
NCRYPT_PAD_PKCS1_FLAG = 0x02
RSA_PUBLIC_MAGIC = 0x31415352  # "RSA1", BCRYPT_RSAPUBLIC_MAGIC
CACHE_PROPERTIES = ("NgcCacheType", "NgcCacheTypeProperty")
_NATIVE_OPERATION = threading.Lock()

DWORD = ct.c_uint32
STATUS = ct.c_int32
HANDLE = ct.c_void_p
PVOID = ct.c_void_p


class HelloError(Exception):
    """Safe, non-secret diagnostic suitable for the local UI."""


class HelloCancelled(HelloError):
    pass


class HelloUnavailable(HelloError):
    pass


class NativeError(HelloError):
    def __init__(self, operation: str, code: int):
        self.code = code & 0xFFFFFFFF
        super().__init__(t("hello.error.native", operation=operation, code=f"{self.code:08X}"))


def wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


def validate_record_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise HelloError(t("hello.error.invalidSetup"))
    return value


@contextmanager
def native_operation() -> Iterator[None]:
    # Never queue a second OS prompt behind an abandoned/slow one.
    if not _NATIVE_OPERATION.acquire(blocking=False):
        raise HelloError(t("hello.error.stillClosing"))
    try:
        yield
    finally:
        _NATIVE_OPERATION.release()


class OAEPInfo(ct.Structure):
    _fields_ = [("algorithm", ct.c_wchar_p), ("label", PVOID), ("label_size", DWORD)]


class WindowsHello:
    """One operation's CNG bindings; handles are never cached between unlocks."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise HelloUnavailable(t("hello.error.onlyWindows"))
        try:
            # Load the OS DLL only from System32, not an application/current directory.
            self.dll = ct.WinDLL("ncrypt.dll", winmode=0x00000800)
        except (OSError, AttributeError) as exc:
            raise HelloUnavailable(t("hello.error.componentUnavailable")) from exc
        signatures = {
            "NCryptOpenStorageProvider": [ct.POINTER(HANDLE), ct.c_wchar_p, DWORD],
            "NCryptCreatePersistedKey": [HANDLE, ct.POINTER(HANDLE), ct.c_wchar_p,
                                         ct.c_wchar_p, DWORD, DWORD],
            "NCryptOpenKey": [HANDLE, ct.POINTER(HANDLE), ct.c_wchar_p, DWORD, DWORD],
            "NCryptSetProperty": [HANDLE, ct.c_wchar_p, PVOID, DWORD, DWORD],
            "NCryptGetProperty": [HANDLE, ct.c_wchar_p, PVOID, DWORD, ct.POINTER(DWORD), DWORD],
            "NCryptFinalizeKey": [HANDLE, DWORD],
            "NCryptDeleteKey": [HANDLE, DWORD],
            "NCryptFreeObject": [HANDLE],
            "NCryptEncrypt": [HANDLE, PVOID, DWORD, PVOID, PVOID, DWORD, ct.POINTER(DWORD), DWORD],
            "NCryptDecrypt": [HANDLE, PVOID, DWORD, PVOID, PVOID, DWORD, ct.POINTER(DWORD), DWORD],
            "NCryptExportKey": [HANDLE, HANDLE, ct.c_wchar_p, PVOID, PVOID, DWORD, ct.POINTER(DWORD), DWORD],
        }
        for name, arguments in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes = arguments
            function.restype = STATUS

    @staticmethod
    def supported_platform() -> bool:
        return sys.platform == "win32"

    @staticmethod
    def _check(code: int, operation: str) -> None:
        code = int(code) & 0xFFFFFFFF
        if code in CANCEL_CODES:
            raise HelloCancelled(t("hello.error.cancelledLocked"))
        if code:
            raise NativeError(operation, code)

    @staticmethod
    def _name(record_id: str) -> str:
        validate_record_id(record_id)
        try:
            import win32api
            import win32con
            import win32security
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
                user = win32security.ConvertSidToStringSid(sid)
            finally:
                token.Close()
        except Exception as exc:
            raise HelloUnavailable(t("hello.error.noAccount")) from exc
        return f"{user}//LocalGateKeys//{record_id}"

    @contextmanager
    def _provider(self) -> Iterator[HANDLE]:
        handle = HANDLE()
        self._check(self.dll.NCryptOpenStorageProvider(ct.byref(handle), PROVIDER, 0), "opening the provider")
        try:
            yield handle
        finally:
            self.dll.NCryptFreeObject(handle)

    @contextmanager
    def _key(self, record_id: str, *, silent: bool = True) -> Iterator[HANDLE]:
        # The Passport provider keeps NCRYPT_SILENT_FLAG for the handle's lifetime: a key
        # opened silently answers every later decrypt with NTE_SILENT_CONTEXT and never
        # shows the Hello prompt. Open it with UI allowed when a prompt must follow.
        with self._provider() as provider:
            key = HANDLE()
            self._check(self.dll.NCryptOpenKey(provider, ct.byref(key), self._name(record_id),
                                               0, NCRYPT_SILENT_FLAG if silent else 0), "opening the local key")
            try:
                yield key
            finally:
                self.dll.NCryptFreeObject(key)

    def _set(self, key: HANDLE, name: str, value: object) -> None:
        self._check(self.dll.NCryptSetProperty(key, name, ct.byref(value), ct.sizeof(value), 0),
                    f"setting {name}")

    def _get_int(self, key: HANDLE, name: str) -> int:
        value, length = DWORD(), DWORD()
        self._check(self.dll.NCryptGetProperty(key, name, ct.byref(value), ct.sizeof(value),
                                                ct.byref(length), 0), f"checking {name}")
        if length.value != ct.sizeof(value):
            raise HelloError(t("hello.error.invalidPolicy"))
        return int(value.value)

    def _set_cache(self, key: HANDLE) -> None:
        for name in CACHE_PROPERTIES:
            try:
                self._set(key, name, DWORD(1))  # Authentication mandatory for this key.
                return
            except NativeError as exc:
                if exc.code not in (0x80090029, 0x80090027, 0x80090011):
                    raise
        raise HelloUnavailable(t("hello.error.noFreshVerification"))

    def _policy(self, key: HANDLE) -> None:
        usage = self._get_int(key, "Key Usage")
        if not usage & 1 or usage & 8:  # Imported keys must not substitute for the generated key.
            raise HelloError(t("hello.error.unsafeUsage"))
        if self._get_int(key, "Export Policy") != 0:
            raise HelloError(t("hello.error.exportable"))
        if self._get_int(key, "Length") != RSA_BITS:
            raise HelloError(t("hello.error.keySize"))
        for name in CACHE_PROPERTIES:
            try:
                value = self._get_int(key, name)
                break
            except NativeError as exc:
                if exc.code not in (0x80090029, 0x80090027, 0x80090011):
                    raise
        else:
            raise HelloUnavailable(t("hello.error.policyUnchecked"))
        if value != 1:
            raise HelloError(t("hello.error.notRequiring"))

    def _context(self, key: HANDLE, hwnd: int, message: str) -> None:
        if not isinstance(hwnd, int) or hwnd <= 0:
            raise HelloError(t("hello.error.windowRequired"))
        self._set(key, "HWND Handle", HANDLE(hwnd))
        self._set(key, "Use Context", ct.create_unicode_buffer(message[:160]))

    def _crypt(self, key: HANDLE, data: bytes | bytearray, *, decrypt: bool, silent: bool = False,
               oaep_hash: str = "SHA256") -> bytearray:
        if oaep_hash not in OAEP_HASHES:
            raise HelloError(t("hello.error.damaged"))
        if (decrypt and len(data) != RSA_BYTES) or (not decrypt and len(data) != 32):
            raise HelloError(t("hello.error.keyLength"))
        source = (ct.c_ubyte * len(data)).from_buffer_copy(data)
        target = (ct.c_ubyte * RSA_BYTES)()
        size = DWORD()
        if oaep_hash == "PKCS1":
            padding_info, pad_flag = None, NCRYPT_PAD_PKCS1_FLAG
        else:
            padding = OAEPInfo(oaep_hash, None, 0)
            padding_info, pad_flag = ct.byref(padding), NCRYPT_PAD_OAEP_FLAG
        flags = pad_flag | (NCRYPT_SILENT_FLAG if silent else 0)
        function = self.dll.NCryptDecrypt if decrypt else self.dll.NCryptEncrypt
        try:
            self._check(function(key, source, len(data), padding_info, target,
                                 len(target), ct.byref(size), flags), "decrypting" if decrypt else "encrypting")
            expected = 32 if decrypt else RSA_BYTES
            if size.value != expected:
                raise HelloError(t("hello.error.invalidKeyMaterial"))
            return bytearray(target[:size.value])
        finally:
            ct.memset(ct.addressof(source), 0, ct.sizeof(source))
            ct.memset(ct.addressof(target), 0, ct.sizeof(target))

    def create(self, record_id: str, hwnd: int) -> None:
        """Create only an application-owned, non-exportable, per-use Hello key."""
        with self._provider() as provider:
            key = HANDLE()
            self._context(provider, hwnd, t("hello.prompt.setup"))
            self._check(self.dll.NCryptCreatePersistedKey(provider, ct.byref(key), "RSA",
                                                         self._name(record_id), 0, 0), "creating the local key")
            delete_on_exit = True
            try:
                self._set(key, "Length", DWORD(RSA_BITS))
                self._set(key, "Key Usage", DWORD(3))
                self._set(key, "Export Policy", DWORD(0))
                self._set_cache(key)
                self._context(key, hwnd, t("hello.prompt.setup"))
                self._check(self.dll.NCryptFinalizeKey(key, 0), "finalizing the local key")
                self._policy(key)
                delete_on_exit = False
            finally:
                if delete_on_exit:
                    # A successful delete also frees the handle. Never free twice.
                    status = int(self.dll.NCryptDeleteKey(key, NCRYPT_SILENT_FLAG)) & 0xFFFFFFFF
                    if status:
                        self.dll.NCryptFreeObject(key)
                else:
                    self.dll.NCryptFreeObject(key)

    def _public_key(self, key: HANDLE) -> Any:
        from cryptography.hazmat.primitives.asymmetric import rsa
        size = DWORD()
        self._check(self.dll.NCryptExportKey(key, None, "RSAPUBLICBLOB", None, None, 0, ct.byref(size),
                                             NCRYPT_SILENT_FLAG), "reading the public key")
        if not 24 < size.value <= 4096:
            raise HelloError(t("hello.error.invalidKeyMaterial"))
        blob = (ct.c_ubyte * size.value)()
        self._check(self.dll.NCryptExportKey(key, None, "RSAPUBLICBLOB", None, blob, size.value,
                                             ct.byref(size), NCRYPT_SILENT_FLAG), "reading the public key")
        raw = bytes(blob[:size.value])
        magic, bits, exp_len, mod_len = struct.unpack_from("<4I", raw)
        if (magic != RSA_PUBLIC_MAGIC or bits != RSA_BITS or mod_len != RSA_BYTES
                or not 0 < exp_len <= 8 or len(raw) < 24 + exp_len + mod_len):
            raise HelloError(t("hello.error.invalidKeyMaterial"))
        exponent = int.from_bytes(raw[24:24 + exp_len], "big")
        modulus = int.from_bytes(raw[24 + exp_len:24 + exp_len + mod_len], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def wrap(self, record_id: str, secret: bytearray, oaep_hash: str = "SHA256") -> bytes:
        """Encrypt with the key's public half in software.

        Some Passport providers reject NCryptEncrypt parameters (0x80090027) even
        though the public operation needs no hardware; doing it here avoids that.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        if oaep_hash not in OAEP_HASHES:
            raise HelloError(t("hello.error.damaged"))
        if len(secret) != 32:
            raise HelloError(t("hello.error.keyLength"))
        with self._key(record_id) as key:
            self._policy(key)
            public = self._public_key(key)
        if oaep_hash == "PKCS1":
            scheme = padding.PKCS1v15()
        else:
            algorithm = hashes.SHA256() if oaep_hash == "SHA256" else hashes.SHA1()  # noqa: S303 - OAEP-SHA1 is sound for key wrapping
            scheme = padding.OAEP(mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None)
        wrapped = public.encrypt(bytes(secret), scheme)
        if len(wrapped) != RSA_BYTES:
            raise HelloError(t("hello.error.invalidKeyMaterial"))
        return wrapped

    def unwrap(self, record_id: str, wrapped: bytes, hwnd: int, oaep_hash: str = "SHA256") -> bytearray:
        with self._key(record_id, silent=False) as key:
            self._policy(key)
            self._context(key, hwnd, t("hello.prompt.unlock"))
            self._set(key, "PinCacheIsGestureRequired", DWORD(1))
            # Verify that the *actual private-key operation*, not a UI boolean,
            # refuses a silent request. An unexpected result never grants access.
            try:
                unguarded = self._crypt(key, wrapped, decrypt=True, silent=True, oaep_hash=oaep_hash)
            except NativeError as exc:
                if exc.code != NTE_SILENT_CONTEXT:
                    raise
            else:
                wipe(unguarded)
                raise HelloError(t("hello.error.noFreshDecrypt"))
            self._set(key, "PinCacheIsGestureRequired", DWORD(1))
            if oaep_hash != "PKCS1":
                return self._crypt(key, wrapped, decrypt=True, oaep_hash=oaep_hash)
            try:
                return self._crypt(key, wrapped, decrypt=True, oaep_hash=oaep_hash)
            except HelloCancelled:
                raise
            except HelloError:
                # One message for every PKCS#1 v1.5 failure: no padding/length oracle.
                raise HelloError(t("hello.error.invalidKeyMaterial")) from None

    def delete(self, record_id: str) -> None:
        """Delete this app's random key only, never the Windows Hello container."""
        with self._provider() as provider:
            key = HANDLE()
            status = int(self.dll.NCryptOpenKey(provider, ct.byref(key), self._name(record_id),
                                                0, NCRYPT_SILENT_FLAG)) & 0xFFFFFFFF
            if status in MISSING_KEY_CODES:
                return
            self._check(status, "opening the local key for removal")
            deleted = False
            try:
                self._check(self.dll.NCryptDeleteKey(key, NCRYPT_SILENT_FLAG), "removing the local key")
                deleted = True
            finally:
                if not deleted:
                    self.dll.NCryptFreeObject(key)
