"""What the SSH agent serves: allow-listed vault SSH keys, each signature approved by the user.

Listing is never interactive: a locked vault lists nothing. A signature unlocks first (the compact unlock in the
popup), then asks through the shared approval layer, then re-checks that the vault is still unlocked and the key
still offered before it signs. The whole request has one deadline (95 s), so a client never hangs on a prompt
nobody answers. Nothing here logs key material, data to sign, signatures or item titles.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..i18n import t
from ..local_clients import ApprovalRequest, ClientIdentity
from ..ssh_keys import SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512, load_private_key

_log = logging.getLogger(__name__)
SIGN_DEADLINE = 95.0
VAULT_LOCK_TIMEOUT = 5.0
KNOWN_HOSTS_MAX_BYTES = 4 * 1024 * 1024
SUPPORTED_KEY_TYPES = frozenset({"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ssh-rsa"})
# Host keys only (session-bind): nistp521 hosts are named too, though the agent serves no P-521 keys.
_CURVES = {b"nistp256": (ec.SECP256R1, hashes.SHA256), b"nistp384": (ec.SECP384R1, hashes.SHA384),
           b"nistp521": (ec.SECP521R1, hashes.SHA512)}
_RSA_SIGNATURES = {b"rsa-sha2-256": hashes.SHA256, b"rsa-sha2-512": hashes.SHA512}
_SIGN_INTENT = "ssh agent signature approved by the user"


def _strings(blob: bytes, count: int) -> list[bytes] | None:
    """The first ``count`` SSH strings of ``blob``, or None when it is shorter."""
    out, pos = [], 0
    for _ in range(count):
        if pos + 4 > len(blob):
            return None
        (length,) = struct.unpack_from(">I", blob, pos)
        end = pos + 4 + length
        if end > len(blob):
            return None
        out.append(blob[pos + 4:end])
        pos = end
    return out


def _blob_type(blob: bytes) -> str:
    parts = _strings(blob, 1)
    return parts[0].decode("ascii", "replace") if parts else ""


def _fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def _public_line_blob(line: Any) -> tuple[bytes, str] | None:
    """(blob, comment) from an OpenSSH public key line whose type matches its blob."""
    if not isinstance(line, str):
        return None
    fields = line.strip().split(None, 2)
    if len(fields) < 2 or fields[0] not in SUPPORTED_KEY_TYPES:
        return None
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    if _blob_type(blob) != fields[0]:
        return None
    return blob, (fields[2].strip() if len(fields) > 2 else "")


def _int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def verify_ssh_signature(public_blob: bytes, signature_blob: bytes, data: bytes) -> bool:
    """Check an SSH signature blob over ``data`` (ed25519, ECDSA P-256/384/521, RSA SHA-2; never SHA-1)."""
    try:
        key_type = _blob_type(public_blob)
        signature = _strings(signature_blob, 2)
        if signature is None:
            return False
        algorithm, raw = signature
        if key_type == "ssh-ed25519" and algorithm == b"ssh-ed25519":
            parts = _strings(public_blob, 2)
            if parts is None:
                return False
            ed25519.Ed25519PublicKey.from_public_bytes(parts[1]).verify(raw, data)
            return True
        if key_type.startswith("ecdsa-sha2-") and algorithm == key_type.encode("ascii"):
            parts = _strings(public_blob, 3)
            if parts is None or parts[1] not in _CURVES or key_type != "ecdsa-sha2-" + parts[1].decode("ascii"):
                return False
            curve_cls, hash_cls = _CURVES[parts[1]]
            numbers = _strings(raw, 2)
            if numbers is None:
                return False
            public = ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), parts[2])
            public.verify(encode_dss_signature(_int(numbers[0]), _int(numbers[1])), data, ec.ECDSA(hash_cls()))
            return True
        if key_type == "ssh-rsa" and algorithm in _RSA_SIGNATURES:
            parts = _strings(public_blob, 3)
            if parts is None:
                return False
            public = rsa.RSAPublicNumbers(_int(parts[1]), _int(parts[2])).public_key()
            public.verify(raw, data, padding.PKCS1v15(), _RSA_SIGNATURES[algorithm]())
            return True
    except (InvalidSignature, ValueError, TypeError, UnicodeDecodeError):
        return False
    return False


class SshAgentService:
    def __init__(self, host: Any, *, known_hosts: Path | None = None, deadline: float = SIGN_DEADLINE,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._host = host
        self._known_hosts = known_hosts if known_hosts is not None else Path.home() / ".ssh" / "known_hosts"
        self._deadline = float(deadline)
        self._clock = clock

    # ---------------------------------------------------------------- keys
    def _allowed_ids(self) -> list[str]:
        ids = getattr(self._host.settings, "developer_ssh_keys", None)
        return [value for value in ids if isinstance(value, str)] if isinstance(ids, list) else []

    def _offered(self) -> list[tuple[str, str, bytes, str]]:
        """(item id, title, public blob, comment) of every allow-listed SSH key item; call with the vault lock."""
        session = self._host.session
        if session is None:
            return []
        rows = []
        for item_id in self._allowed_ids():
            item = session.item_service.get_item(item_id)
            if not item or item.get("kind") != "ssh_key":
                continue
            parsed = _public_line_blob((item.get("payload") or {}).get("public_key"))
            if parsed is None:
                continue  # no usable public half (an encrypted key saved without its passphrase, sk-*, PuTTY)
            rows.append((item_id, str(item.get("title") or ""), parsed[0], parsed[1]))
        return rows

    def _with_vault(self, fn: Callable[[], Any], timeout: float = VAULT_LOCK_TIMEOUT) -> Any:
        return self._host.run_on_ui(fn, timeout=max(0.0, timeout))

    def identities(self) -> list[tuple[bytes, str]]:
        """Allow-listed keys while unlocked; never prompts. The comment is the public key's own, not the item title."""
        if self._host.session is None:
            return []
        try:
            rows = self._with_vault(self._offered)
        except Exception as exc:  # noqa: BLE001 - busy vault or a malformed item: list nothing
            _log.info("SSH agent could not list keys: %s", type(exc).__name__)
            return []
        return [(blob, comment) for _id, _title, blob, comment in rows]

    # ---------------------------------------------------------------- signing
    def _until(self, deadline: float, fn: Callable[[], Any]) -> bool:
        """Run a wait for the user on its own thread; False when it is not True by the deadline."""
        remaining = deadline - self._clock()
        if remaining <= 0:
            return False
        result: list[Any] = []

        def run() -> None:
            try:
                result.append(fn())
            except Exception as exc:  # noqa: BLE001 - a failed prompt or unlock is a refusal
                _log.info("SSH agent wait failed: %s", type(exc).__name__)
        worker = threading.Thread(target=run, name="lgk-ssh-agent-wait", daemon=True)
        worker.start()
        worker.join(remaining)
        return bool(result) and result[0] is True and self._clock() < deadline

    def sign(self, blob: bytes, data: bytes, flags: int, client: ClientIdentity,
             bound_host: str | None) -> bytes | None:
        deadline = self._clock() + self._deadline
        try:
            return self._sign(blob, data, int(flags), client, bound_host, deadline)
        except Exception as exc:  # noqa: BLE001 - the client gets FAILURE
            _log.warning("SSH agent signature failed: %s", getattr(exc, "code", type(exc).__name__))
            return None

    def _sign(self, blob: bytes, data: bytes, flags: int, client: ClientIdentity, bound_host: str | None,
              deadline: float) -> bytes | None:
        key_type = _blob_type(blob)
        if key_type not in SUPPORTED_KEY_TYPES:
            return None
        if key_type == "ssh-rsa" and not flags & (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512):
            _log.info("SSH agent refused an SHA-1 ssh-rsa signature")
            return None
        if self._host.session is None and not self._until(deadline, self._host.ensure_unlocked):
            return None
        match = self._with_vault(lambda: next(((i, title) for i, title, b, _c in self._offered() if b == blob), None),
                                 min(VAULT_LOCK_TIMEOUT, deadline - self._clock()))
        if match is None:
            return None
        item_id, title = match
        detail = t("ssh_agent.detail.host", host=bound_host) if bound_host else ""
        request = ApprovalRequest("ssh_sign", client, item_id, title, detail)
        if not self._until(deadline, lambda: self._host.approve_local_client(request)):
            _log.info("SSH agent signature not approved")
            return None
        secret = self._with_vault(lambda: self._secret(item_id, blob), min(VAULT_LOCK_TIMEOUT, deadline - self._clock()))
        if secret is None:
            return None  # locked, or the key stopped being offered, while the prompt was open
        key = load_private_key(secret[0], secret[1] or None)
        if key.public_blob != blob or self._clock() >= deadline:
            return None
        return key.sign(data, flags)

    def _secret(self, item_id: str, blob: bytes) -> tuple[str, str] | None:
        session = self._host.session
        if session is None or not any(i == item_id and b == blob for i, _t, b, _c in self._offered()):
            return None
        items = session.item_service
        return (items.reveal_secret(item_id, "private_key", intent=_SIGN_INTENT),
                items.reveal_secret(item_id, "passphrase", intent=_SIGN_INTENT))

    # ---------------------------------------------------------------- session-bind
    def verify_bind(self, host_key: bytes, session_id: bytes, signature: bytes) -> bool:
        return verify_ssh_signature(host_key, signature, session_id)

    def host_name_for(self, host_key: bytes) -> str:
        """The first unhashed ``known_hosts`` name for this host key, else its fingerprint."""
        try:
            with open(self._known_hosts, "rb") as handle:
                text = handle.read(KNOWN_HOSTS_MAX_BYTES).decode("utf-8", "replace")
        except OSError:
            return _fingerprint(host_key)
        encoded = base64.b64encode(host_key).decode("ascii")
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 3 or fields[0].startswith(("#", "@", "|")):
                continue  # comments, @revoked / @cert-authority, hashed names
            if fields[2] != encoded:
                continue
            for name in fields[0].split(","):
                if not name or name.startswith("!") or "*" in name or "?" in name:
                    continue
                if name.startswith("[") and "]:" in name:
                    host, port = name[1:].split("]:", 1)
                    return host if port == "22" else f"{host}:{port}"
                return name
        return _fingerprint(host_key)
