"""Hardware security key (FIDO2) support through the Windows WebAuthn API.

``webauthn.dll`` is the supported way for an ordinary (non-admin) desktop app to
talk to FIDO2 security keys since Windows 10 1903: raw CTAP over HID needs admin.
Windows shows its own "Windows Security" dialog for the PIN and touch, so this
module never sees the key's PIN.

Only the ``hmac-secret`` extension is used: a credential made with it returns a
32-byte secret per salt at get-assertion time.  The secret is derived on the key
from a per-credential random value and never leaves it.  Assertion signatures are
not checked: nothing here trusts the assertion, only the secret, and a wrong
secret simply fails to decrypt the wrapped data key (AES-GCM).

Assertion-time salts (``pHmacSecretSaltValues``) need WebAuthn API version 4
(Windows 11); older versions disable the route.  Windows hashes each salt PRF
style (SHA-256("WebAuthn PRF" || 0x00 || salt)) before sending it to the key, as
browsers do; the raw-salt flag is not used, so the same credential would also
answer a WebAuthn PRF request for the same relying party and salt.

User verification (PIN or on-key biometrics) is required both when the
credential is made and at every assertion: CTAP2 keys return a *different*
hmac-secret with and without verification, and requiring it means a stolen key
alone cannot unlock.

The relying party id is a fixed, non-web name (``RP_ID``).  webauthn.dll does not
check an RP id against an origin for desktop callers (browsers do that before
they call it), so any well-formed name is accepted; a ``.local`` name can never
be claimed by a public website, so a phishing page cannot ask the key for this
credential's secret even if it had the credential id and salt.
"""
from __future__ import annotations

import base64
import ctypes as ct
import json
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol

from .i18n import t

RP_ID = "localgatekeys.local"
RP_NAME = "LocalGateKeys"
ORIGIN = "https://" + RP_ID
MIN_API_VERSION = 4
TIMEOUT_MS = 60_000
SECRET_BYTES = 32
MAX_CREDENTIAL_ID_BYTES = 1023

# webauthn.h constants.
COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7
COSE_ALGORITHM_EDDSA_ED25519 = -8
COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256 = -257
CREDENTIAL_TYPE_PUBLIC_KEY = "public-key"
HASH_ALGORITHM_SHA_256 = "SHA-256"
EXTENSIONS_IDENTIFIER_HMAC_SECRET = "hmac-secret"
AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2
USER_VERIFICATION_REQUIREMENT_REQUIRED = 1
ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1
RP_ENTITY_INFORMATION_VERSION = 1
USER_ENTITY_INFORMATION_VERSION = 1
CLIENT_DATA_VERSION = 1
COSE_CREDENTIAL_PARAMETER_VERSION = 1
CREDENTIAL_VERSION = 1
# Version 3 is the newest make-credential layout every API version understands
# (cancellation id + exclude list); nothing newer is needed.
MAKE_CREDENTIAL_OPTIONS_VERSION = 3
# Version 6 (API version 4) added pHmacSecretSaltValues.
GET_ASSERTION_OPTIONS_VERSION = 6
ASSERTION_VERSION_WITH_HMAC_SECRET = 3
ATTESTATION_VERSION_WITH_EXTENSIONS = 2

NTE_INVALID_PARAMETER = 0x80090027
NTE_NOT_FOUND = 0x80090011
NTE_NOT_SUPPORTED = 0x80090029
NTE_DEVICE_NOT_FOUND = 0x80090035
CANCEL_CODES = {0x80090036, 0x800704C7}  # NTE_USER_CANCELLED, HRESULT_FROM_WIN32(ERROR_CANCELLED)
TIMEOUT_CODES = {0x800705B4}  # HRESULT_FROM_WIN32(ERROR_TIMEOUT)
_NATIVE_OPERATION = threading.Lock()

DWORD = ct.c_uint32
LONG = ct.c_int32
BOOL = ct.c_int32
HRESULT = ct.c_int32
PBYTE = ct.POINTER(ct.c_ubyte)
PVOID = ct.c_void_p


class SecurityKeyError(Exception):
    """Safe, non-secret diagnostic suitable for the local UI."""


class SecurityKeyCancelled(SecurityKeyError):
    pass


class SecurityKeyUnavailable(SecurityKeyError):
    pass


class SecurityKeyNativeError(SecurityKeyError):
    def __init__(self, operation: str, code: int):
        self.code = code & 0xFFFFFFFF
        super().__init__(t("securityKey.error.native", operation=operation, code=f"{self.code:08X}"))


def wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


@contextmanager
def native_operation() -> Iterator[None]:
    # Never queue a second Windows Security dialog behind an abandoned/slow one.
    if not _NATIVE_OPERATION.acquire(blocking=False):
        raise SecurityKeyError(t("securityKey.error.stillClosing"))
    try:
        yield
    finally:
        _NATIVE_OPERATION.release()


class SecurityKeyApi(Protocol):
    """What ``fido_unlock`` needs from the platform; tests supply a simulated key."""

    def api_version(self) -> int: ...

    def make_credential(self, hwnd: int, rp_id: str, user_id: bytes) -> bytes: ...

    def hmac_secret(self, hwnd: int, rp_id: str, credential_id: bytes, salt: bytes) -> bytearray: ...


# ----------------------------------------------------------------- structures
class GUID(ct.Structure):
    _fields_ = [("Data1", DWORD), ("Data2", ct.c_uint16), ("Data3", ct.c_uint16), ("Data4", ct.c_ubyte * 8)]


class RpEntityInformation(ct.Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszId", ct.c_wchar_p), ("pwszName", ct.c_wchar_p),
                ("pwszIcon", ct.c_wchar_p)]


class UserEntityInformation(ct.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbId", DWORD), ("pbId", PBYTE), ("pwszName", ct.c_wchar_p),
                ("pwszIcon", ct.c_wchar_p), ("pwszDisplayName", ct.c_wchar_p)]


class ClientData(ct.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbClientDataJSON", DWORD), ("pbClientDataJSON", PBYTE),
                ("pwszHashAlgId", ct.c_wchar_p)]


class CoseCredentialParameter(ct.Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszCredentialType", ct.c_wchar_p), ("lAlg", LONG)]


class CoseCredentialParameters(ct.Structure):
    _fields_ = [("cCredentialParameters", DWORD), ("pCredentialParameters", ct.POINTER(CoseCredentialParameter))]


class Credential(ct.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbId", DWORD), ("pbId", PBYTE), ("pwszCredentialType", ct.c_wchar_p)]


class Credentials(ct.Structure):
    _fields_ = [("cCredentials", DWORD), ("pCredentials", ct.POINTER(Credential))]


class Extension(ct.Structure):
    _fields_ = [("pwszExtensionIdentifier", ct.c_wchar_p), ("cbExtension", DWORD), ("pvExtension", PVOID)]


class Extensions(ct.Structure):
    _fields_ = [("cExtensions", DWORD), ("pExtensions", ct.POINTER(Extension))]


class HmacSecretSalt(ct.Structure):
    _fields_ = [("cbFirst", DWORD), ("pbFirst", PBYTE), ("cbSecond", DWORD), ("pbSecond", PBYTE)]


class CredWithHmacSecretSalt(ct.Structure):
    _fields_ = [("cbCredID", DWORD), ("pbCredID", PBYTE), ("pHmacSecretSalt", ct.POINTER(HmacSecretSalt))]


class HmacSecretSaltValues(ct.Structure):
    _fields_ = [("pGlobalHmacSalt", ct.POINTER(HmacSecretSalt)), ("cCredWithHmacSecretSaltList", DWORD),
                ("pCredWithHmacSecretSaltList", ct.POINTER(CredWithHmacSecretSalt))]


class MakeCredentialOptions(ct.Structure):
    """WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS up to version 3."""
    _fields_ = [("dwVersion", DWORD), ("dwTimeoutMilliseconds", DWORD), ("CredentialList", Credentials),
                ("Extensions", Extensions), ("dwAuthenticatorAttachment", DWORD), ("bRequireResidentKey", BOOL),
                ("dwUserVerificationRequirement", DWORD), ("dwAttestationConveyancePreference", DWORD),
                ("dwFlags", DWORD),
                ("pCancellationId", ct.POINTER(GUID)),  # v2
                ("pExcludeCredentialList", PVOID)]  # v3


class GetAssertionOptions(ct.Structure):
    """WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS up to version 6."""
    _fields_ = [("dwVersion", DWORD), ("dwTimeoutMilliseconds", DWORD), ("CredentialList", Credentials),
                ("Extensions", Extensions), ("dwAuthenticatorAttachment", DWORD),
                ("dwUserVerificationRequirement", DWORD), ("dwFlags", DWORD),
                ("pwszU2fAppId", ct.c_wchar_p), ("pbU2fAppId", ct.POINTER(BOOL)),  # v2
                ("pCancellationId", ct.POINTER(GUID)),  # v3
                ("pAllowCredentialList", PVOID),  # v4
                ("dwCredLargeBlobOperation", DWORD), ("cbCredLargeBlob", DWORD), ("pbCredLargeBlob", PBYTE),  # v5
                ("pHmacSecretSaltValues", ct.POINTER(HmacSecretSaltValues)), ("bBrowserInPrivateMode", BOOL)]  # v6


class CredentialAttestation(ct.Structure):
    """WEBAUTHN_CREDENTIAL_ATTESTATION up to version 2 (later fields are never read)."""
    _fields_ = [("dwVersion", DWORD), ("pwszFormatType", ct.c_wchar_p),
                ("cbAuthenticatorData", DWORD), ("pbAuthenticatorData", PBYTE),
                ("cbAttestation", DWORD), ("pbAttestation", PBYTE),
                ("dwAttestationDecodeType", DWORD), ("pvAttestationDecode", PVOID),
                ("cbAttestationObject", DWORD), ("pbAttestationObject", PBYTE),
                ("cbCredentialId", DWORD), ("pbCredentialId", PBYTE),
                ("Extensions", Extensions)]  # v2


class Assertion(ct.Structure):
    """WEBAUTHN_ASSERTION up to version 3 (later fields are never read)."""
    _fields_ = [("dwVersion", DWORD), ("cbAuthenticatorData", DWORD), ("pbAuthenticatorData", PBYTE),
                ("cbSignature", DWORD), ("pbSignature", PBYTE), ("Credential", Credential),
                ("cbUserId", DWORD), ("pbUserId", PBYTE),
                ("Extensions", Extensions), ("cbCredLargeBlob", DWORD), ("pbCredLargeBlob", PBYTE),
                ("dwCredLargeBlobStatus", DWORD),  # v2
                ("pHmacSecret", ct.POINTER(HmacSecretSalt))]  # v3


def _buffer(data: bytes | bytearray) -> ct.Array:
    return (ct.c_ubyte * max(1, len(data))).from_buffer_copy(bytes(data) or b"\0")


def _client_data(kind: str) -> bytes:
    # Nothing verifies the assertion signature, so the challenge only has to be fresh.
    challenge = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    return json.dumps({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
                      separators=(",", ":")).encode("utf-8")


def _require_window(hwnd: int) -> None:
    if not isinstance(hwnd, int) or hwnd <= 0:
        raise SecurityKeyError(t("securityKey.error.windowRequired"))


def supported_platform() -> bool:
    return sys.platform == "win32"


class WebAuthn:
    """One operation's webauthn.dll bindings; nothing is cached between unlocks."""

    def __init__(self) -> None:
        if not supported_platform():
            raise SecurityKeyUnavailable(t("securityKey.error.onlyWindows"))
        try:
            # Load the OS DLL only from System32, not an application/current directory.
            self.dll = ct.WinDLL("webauthn.dll", winmode=0x00000800)
            version = self.dll.WebAuthNGetApiVersionNumber
        except (OSError, AttributeError) as exc:
            raise SecurityKeyUnavailable(t("securityKey.error.componentUnavailable")) from exc
        version.argtypes = []
        version.restype = DWORD
        signatures = {
            "WebAuthNAuthenticatorMakeCredential": (HRESULT, [
                PVOID, ct.POINTER(RpEntityInformation), ct.POINTER(UserEntityInformation),
                ct.POINTER(CoseCredentialParameters), ct.POINTER(ClientData),
                ct.POINTER(MakeCredentialOptions), ct.POINTER(ct.POINTER(CredentialAttestation))]),
            "WebAuthNAuthenticatorGetAssertion": (HRESULT, [
                PVOID, ct.c_wchar_p, ct.POINTER(ClientData), ct.POINTER(GetAssertionOptions),
                ct.POINTER(ct.POINTER(Assertion))]),
            "WebAuthNFreeCredentialAttestation": (None, [ct.POINTER(CredentialAttestation)]),
            "WebAuthNFreeAssertion": (None, [ct.POINTER(Assertion)]),
        }
        try:
            for name, (restype, arguments) in signatures.items():
                function = getattr(self.dll, name)
                function.argtypes = arguments
                function.restype = restype
        except AttributeError as exc:
            raise SecurityKeyUnavailable(t("securityKey.error.componentUnavailable")) from exc

    def api_version(self) -> int:
        return int(self.dll.WebAuthNGetApiVersionNumber())

    def _require_api(self) -> None:
        version = self.api_version()
        if version < MIN_API_VERSION:
            raise SecurityKeyUnavailable(t("securityKey.error.apiTooOld", version=version))

    @staticmethod
    def _check(code: int, operation: str) -> None:
        code = int(code) & 0xFFFFFFFF
        if code in CANCEL_CODES or code in TIMEOUT_CODES:
            raise SecurityKeyCancelled(t("securityKey.error.cancelled"))
        if code == NTE_NOT_FOUND:
            # Windows' own dialog already said "this security key doesn't look familiar".
            raise SecurityKeyError(t("securityKey.error.unknownKey"))
        if code:
            raise SecurityKeyNativeError(operation, code)

    def make_credential(self, hwnd: int, rp_id: str, user_id: bytes) -> bytes:
        """Create a non-resident, user-verified credential with hmac-secret on a roaming key."""
        _require_window(hwnd)
        self._require_api()
        rp = RpEntityInformation(RP_ENTITY_INFORMATION_VERSION, rp_id, RP_NAME, None)
        user_buffer = _buffer(user_id)
        user = UserEntityInformation(USER_ENTITY_INFORMATION_VERSION, len(user_id),
                                     ct.cast(user_buffer, PBYTE), RP_NAME, None, RP_NAME)
        algorithms = (CoseCredentialParameter * 3)(
            *(CoseCredentialParameter(COSE_CREDENTIAL_PARAMETER_VERSION, CREDENTIAL_TYPE_PUBLIC_KEY, alg)
              for alg in (COSE_ALGORITHM_ECDSA_P256_WITH_SHA256, COSE_ALGORITHM_EDDSA_ED25519,
                          COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256)))
        parameters = CoseCredentialParameters(3, algorithms)
        client_json = _client_data("webauthn.create")
        client_buffer = _buffer(client_json)
        client = ClientData(CLIENT_DATA_VERSION, len(client_json), ct.cast(client_buffer, PBYTE),
                            HASH_ALGORITHM_SHA_256)
        enable = BOOL(1)
        extension = Extension(EXTENSIONS_IDENTIFIER_HMAC_SECRET, ct.sizeof(enable),
                              ct.cast(ct.pointer(enable), PVOID))
        options = MakeCredentialOptions()
        options.dwVersion = MAKE_CREDENTIAL_OPTIONS_VERSION
        options.dwTimeoutMilliseconds = TIMEOUT_MS
        options.Extensions = Extensions(1, ct.pointer(extension))
        options.dwAuthenticatorAttachment = AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        options.bRequireResidentKey = 0
        options.dwUserVerificationRequirement = USER_VERIFICATION_REQUIREMENT_REQUIRED
        options.dwAttestationConveyancePreference = ATTESTATION_CONVEYANCE_PREFERENCE_NONE
        result = ct.POINTER(CredentialAttestation)()
        self._check(self.dll.WebAuthNAuthenticatorMakeCredential(
            PVOID(hwnd), ct.byref(rp), ct.byref(user), ct.byref(parameters), ct.byref(client),
            ct.byref(options), ct.byref(result)), "registering the security key")
        if not result:
            raise SecurityKeyError(t("securityKey.error.invalidResponse"))
        try:
            attestation = result.contents
            size = int(attestation.cbCredentialId)
            if not 1 <= size <= MAX_CREDENTIAL_ID_BYTES or not attestation.pbCredentialId:
                raise SecurityKeyError(t("securityKey.error.invalidResponse"))
            credential_id = ct.string_at(attestation.pbCredentialId, size)
            if attestation.dwVersion >= ATTESTATION_VERSION_WITH_EXTENSIONS:
                for index in range(int(attestation.Extensions.cExtensions)):
                    item = attestation.Extensions.pExtensions[index]
                    if (item.pwszExtensionIdentifier == EXTENSIONS_IDENTIFIER_HMAC_SECRET
                            and item.cbExtension == ct.sizeof(BOOL) and item.pvExtension
                            and not ct.cast(item.pvExtension, ct.POINTER(BOOL)).contents.value):
                        raise SecurityKeyUnavailable(t("securityKey.error.noHmacSecret"))
            return credential_id
        finally:
            self.dll.WebAuthNFreeCredentialAttestation(result)

    def hmac_secret(self, hwnd: int, rp_id: str, credential_id: bytes, salt: bytes) -> bytearray:
        """Ask the key for the credential's 32-byte hmac-secret for ``salt`` (PIN/touch required)."""
        _require_window(hwnd)
        if len(salt) != SECRET_BYTES or not 1 <= len(credential_id) <= MAX_CREDENTIAL_ID_BYTES:
            raise SecurityKeyError(t("securityKey.error.invalidSetup"))
        self._require_api()
        credential_buffer = _buffer(credential_id)
        allowed = Credential(CREDENTIAL_VERSION, len(credential_id), ct.cast(credential_buffer, PBYTE),
                             CREDENTIAL_TYPE_PUBLIC_KEY)
        salt_buffer = _buffer(salt)
        global_salt = HmacSecretSalt(SECRET_BYTES, ct.cast(salt_buffer, PBYTE), 0, None)
        salt_values = HmacSecretSaltValues(ct.pointer(global_salt), 0, None)
        client_json = _client_data("webauthn.get")
        client_buffer = _buffer(client_json)
        client = ClientData(CLIENT_DATA_VERSION, len(client_json), ct.cast(client_buffer, PBYTE),
                            HASH_ALGORITHM_SHA_256)
        options = GetAssertionOptions()
        options.dwVersion = GET_ASSERTION_OPTIONS_VERSION
        options.dwTimeoutMilliseconds = TIMEOUT_MS
        options.CredentialList = Credentials(1, ct.pointer(allowed))
        options.dwAuthenticatorAttachment = AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        options.dwUserVerificationRequirement = USER_VERIFICATION_REQUIREMENT_REQUIRED
        options.pHmacSecretSaltValues = ct.pointer(salt_values)
        result = ct.POINTER(Assertion)()
        self._check(self.dll.WebAuthNAuthenticatorGetAssertion(
            PVOID(hwnd), rp_id, ct.byref(client), ct.byref(options), ct.byref(result)),
            "reading the security key")
        if not result:
            raise SecurityKeyError(t("securityKey.error.invalidResponse"))
        try:
            assertion = result.contents
            used = assertion.Credential
            if (used.cbId != len(credential_id) or not used.pbId
                    or ct.string_at(used.pbId, used.cbId) != bytes(credential_id)):
                raise SecurityKeyError(t("securityKey.error.unknownKey"))
            if assertion.dwVersion < ASSERTION_VERSION_WITH_HMAC_SECRET or not assertion.pHmacSecret:
                raise SecurityKeyUnavailable(t("securityKey.error.noHmacSecret"))
            output = assertion.pHmacSecret.contents
            if output.cbFirst != SECRET_BYTES or not output.pbFirst:
                raise SecurityKeyUnavailable(t("securityKey.error.noHmacSecret"))
            secret = bytearray(ct.string_at(output.pbFirst, SECRET_BYTES))
            # The DLL's copy is freed below; clear it first.
            ct.memset(ct.cast(output.pbFirst, PVOID), 0, SECRET_BYTES)
            return secret
        finally:
            self.dll.WebAuthNFreeAssertion(result)
            ct.memset(ct.addressof(salt_buffer), 0, ct.sizeof(salt_buffer))


def availability(factory=WebAuthn) -> tuple[bool, str]:
    """``(supported, reason)``: whether the option can be offered, and a plain reason when not."""
    if not supported_platform():
        return False, t("securityKey.error.onlyWindows")
    try:
        version = factory().api_version()
    except SecurityKeyError as exc:
        return False, str(exc)
    except Exception:  # noqa: BLE001 - only decides whether the option is shown
        return False, t("securityKey.error.componentUnavailable")
    if version < MIN_API_VERSION:
        return False, t("securityKey.error.apiTooOld", version=version)
    return True, ""
