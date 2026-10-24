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
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

PROVIDER = "Microsoft Passport Key Storage Provider"
RSA_BITS = 2048
RSA_BYTES = RSA_BITS // 8
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_PAD_OAEP_FLAG = 0x04
NTE_SILENT_CONTEXT = 0x80090022
MISSING_KEY_CODES = {0x8009000D, 0x80090016}
CANCEL_CODES = {0x80090036, 0x800704C7}
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
        super().__init__(f"Windows Hello could not complete {operation} (0x{self.code:08X}). "
                         "Use your master password. Check Windows Sign-in options before retrying.")


def wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


def validate_record_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise HelloError("The local Windows Hello setup is invalid. Use your master password.")
    return value


@contextmanager
def native_operation() -> Iterator[None]:
    # Never queue a second OS prompt behind an abandoned/slow one.
    if not _NATIVE_OPERATION.acquire(blocking=False):
        raise HelloError("A Windows Hello operation is still closing. Use your master password "
                         "or cancel the Windows Security prompt before trying again.")
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
            raise HelloUnavailable("Windows Hello is available only on Windows. Use your master password.")
        try:
            # Load the OS DLL only from System32, not an application/current directory.
            self.dll = ct.WinDLL("ncrypt.dll", winmode=0x00000800)
        except (OSError, AttributeError) as exc:
            raise HelloUnavailable("Windows Hello's Windows component is unavailable.") from exc
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
            raise HelloCancelled("Windows Hello was cancelled. Your vault is still locked.")
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
            raise HelloUnavailable("Cannot resolve the current Windows account for Windows Hello.") from exc
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
    def _key(self, record_id: str) -> Iterator[HANDLE]:
        with self._provider() as provider:
            key = HANDLE()
            self._check(self.dll.NCryptOpenKey(provider, ct.byref(key), self._name(record_id),
                                               0, NCRYPT_SILENT_FLAG), "opening the local key")
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
            raise HelloError("Windows Hello returned an invalid key policy. Use your master password.")
        return int(value.value)

    def _set_cache(self, key: HANDLE) -> None:
        for name in CACHE_PROPERTIES:
            try:
                self._set(key, name, DWORD(1))  # Authentication mandatory for this key.
                return
            except NativeError as exc:
                if exc.code not in (0x80090029, 0x80090027, 0x80090011):
                    raise
        raise HelloUnavailable("This Windows Hello provider cannot enforce fresh verification per unlock.")

    def _policy(self, key: HANDLE) -> None:
        usage = self._get_int(key, "Key Usage")
        if not usage & 1 or usage & 8:  # Imported keys must not substitute for the generated key.
            raise HelloError("Windows Hello's key usage policy is unsafe. Use your master password.")
        if self._get_int(key, "Export Policy") != 0:
            raise HelloError("Windows Hello's key is exportable. This unlock route is disabled.")
        if self._get_int(key, "Length") != RSA_BITS:
            raise HelloError("Windows Hello's key size has changed. Use your master password.")
        for name in CACHE_PROPERTIES:
            try:
                value = self._get_int(key, name)
                break
            except NativeError as exc:
                if exc.code not in (0x80090029, 0x80090027, 0x80090011):
                    raise
        else:
            raise HelloUnavailable("Windows Hello's per-use verification policy cannot be checked.")
        if value != 1:
            raise HelloError("Windows Hello is not requiring verification for each use. "
                             "This unlock route is disabled.")

    def _context(self, key: HANDLE, hwnd: int, message: str) -> None:
        if not isinstance(hwnd, int) or hwnd <= 0:
            raise HelloError("A visible LocalGateKeys window is required for Windows Hello.")
        self._set(key, "HWND Handle", HANDLE(hwnd))
        self._set(key, "Use Context", ct.create_unicode_buffer(message[:160]))

    def _crypt(self, key: HANDLE, data: bytes | bytearray, *, decrypt: bool, silent: bool = False) -> bytearray:
        if (decrypt and len(data) != RSA_BYTES) or (not decrypt and len(data) != 32):
            raise HelloError("Windows Hello key material has an invalid length.")
        source = (ct.c_ubyte * len(data)).from_buffer_copy(data)
        target = (ct.c_ubyte * RSA_BYTES)()
        size = DWORD()
        padding = OAEPInfo("SHA256", None, 0)
        flags = NCRYPT_PAD_OAEP_FLAG | (NCRYPT_SILENT_FLAG if silent else 0)
        function = self.dll.NCryptDecrypt if decrypt else self.dll.NCryptEncrypt
        try:
            self._check(function(key, source, len(data), ct.byref(padding), target,
                                 len(target), ct.byref(size), flags), "decrypting" if decrypt else "encrypting")
            expected = 32 if decrypt else RSA_BYTES
            if size.value != expected:
                raise HelloError("Windows Hello returned invalid key material.")
            return bytearray(target[:size.value])
        finally:
            ct.memset(ct.addressof(source), 0, ct.sizeof(source))
            ct.memset(ct.addressof(target), 0, ct.sizeof(target))

    def create(self, record_id: str, hwnd: int) -> None:
        """Create only an application-owned, non-exportable, per-use Hello key."""
        with self._provider() as provider:
            key = HANDLE()
            self._context(provider, hwnd, "Set up local unlocking for LocalGateKeys")
            self._check(self.dll.NCryptCreatePersistedKey(provider, ct.byref(key), "RSA",
                                                         self._name(record_id), 0, 0), "creating the local key")
            delete_on_exit = True
            try:
                self._set(key, "Length", DWORD(RSA_BITS))
                self._set(key, "Key Usage", DWORD(3))
                self._set(key, "Export Policy", DWORD(0))
                self._set_cache(key)
                self._context(key, hwnd, "Set up local unlocking for LocalGateKeys")
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

    def wrap(self, record_id: str, secret: bytearray) -> bytes:
        with self._key(record_id) as key:
            self._policy(key)
            return bytes(self._crypt(key, secret, decrypt=False, silent=True))

    def unwrap(self, record_id: str, wrapped: bytes, hwnd: int) -> bytearray:
        with self._key(record_id) as key:
            self._policy(key)
            self._context(key, hwnd, "Unlock the selected LocalGateKeys profile on this PC")
            self._set(key, "PinCacheIsGestureRequired", DWORD(1))
            # Verify that the *actual private-key operation*, not a UI boolean,
            # refuses a silent request. An unexpected result never grants access.
            try:
                unguarded = self._crypt(key, wrapped, decrypt=True, silent=True)
            except NativeError as exc:
                if exc.code != NTE_SILENT_CONTEXT:
                    raise
            else:
                wipe(unguarded)
                raise HelloError("Windows Hello allowed decryption without fresh verification. "
                                 "Use your master password; re-enroll only after checking Windows.")
            self._set(key, "PinCacheIsGestureRequired", DWORD(1))
            return self._crypt(key, wrapped, decrypt=True)

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
