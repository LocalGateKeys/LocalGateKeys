"""SSH private key loading and signing for the SSH agent and key tools.

Reads OpenSSH (and unencrypted/encrypted PEM) private keys of the four types
the agent serves (ed25519, ECDSA nistp256/nistp384, RSA) and builds SSH wire
format values: public blobs, fingerprints and signature blobs.  Nothing here
touches the disk or logs key material.

Wire formats (RFC 4251): ``string`` is a uint32 length plus bytes, ``mpint`` is
a big-endian two's-complement integer without redundant leading bytes.  A
signature blob is ``string(algorithm) || string(signature)``; the inner ECDSA
signature is ``mpint r || mpint s``.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4

_OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_FOOTER = "-----END OPENSSH PRIVATE KEY-----"
_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_PEM_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)
_CURVES = {
    "nistp256": ("ecdsa-sha2-nistp256", ec.SECP256R1, hashes.SHA256),
    "nistp384": ("ecdsa-sha2-nistp384", ec.SECP384R1, hashes.SHA384),
}


class SshKeyError(Exception):
    """A key could not be used; ``code`` is a short stable identifier."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_mpint(value: int) -> bytes:
    if value == 0:
        return ssh_string(b"")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return ssh_string(raw)


def _read_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(buf):
        raise SshKeyError("unsupported_format")
    (length,) = struct.unpack_from(">I", buf, pos)
    end = pos + 4 + length
    if end > len(buf):
        raise SshKeyError("unsupported_format")
    return buf[pos + 4:end], end


@dataclass(frozen=True)
class AgentKey:
    """A usable private key with its SSH public blob."""

    key_type: str
    public_blob: bytes
    _private: Any

    def public_line(self, comment: str = "") -> str:
        line = f"{self.key_type} {base64.b64encode(self.public_blob).decode('ascii')}"
        return f"{line} {comment}" if comment else line

    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.public_blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def sign(self, data: bytes, flags: int = 0) -> bytes:
        if isinstance(self._private, ed25519.Ed25519PrivateKey):
            return ssh_string(b"ssh-ed25519") + ssh_string(self._private.sign(data))
        if isinstance(self._private, ec.EllipticCurvePrivateKey):
            hash_cls = _CURVES[self.key_type.rsplit("-", 1)[1]][2]
            r, s = decode_dss_signature(self._private.sign(data, ec.ECDSA(hash_cls())))
            return ssh_string(self.key_type.encode("ascii")) + ssh_string(ssh_mpint(r) + ssh_mpint(s))
        if flags & SSH_AGENT_RSA_SHA2_512:
            name, hash_cls = "rsa-sha2-512", hashes.SHA512
        elif flags & SSH_AGENT_RSA_SHA2_256:
            name, hash_cls = "rsa-sha2-256", hashes.SHA256
        else:
            raise SshKeyError("sha1_refused")
        sig = self._private.sign(data, padding.PKCS1v15(), hash_cls())
        return ssh_string(name.encode("ascii")) + ssh_string(sig)


def _agent_key(private: Any) -> AgentKey:
    if isinstance(private, ed25519.Ed25519PrivateKey):
        raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return AgentKey("ssh-ed25519", ssh_string(b"ssh-ed25519") + ssh_string(raw), private)
    if isinstance(private, ec.EllipticCurvePrivateKey):
        for curve_id, (key_type, curve_cls, _hash) in _CURVES.items():
            if isinstance(private.curve, curve_cls):
                point = private.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
                blob = ssh_string(key_type.encode("ascii")) + ssh_string(curve_id.encode("ascii")) + ssh_string(point)
                return AgentKey(key_type, blob, private)
    if isinstance(private, rsa.RSAPrivateKey):
        numbers = private.public_key().public_numbers()
        blob = ssh_string(b"ssh-rsa") + ssh_mpint(numbers.e) + ssh_mpint(numbers.n)
        return AgentKey("ssh-rsa", blob, private)
    raise SshKeyError("unsupported_format")


def _openssh_container(text: str) -> tuple[str, bool]:
    """Return (key type, encrypted) from an OpenSSH container without decrypting."""
    body = "".join(text.strip().removeprefix(_OPENSSH_HEADER).removesuffix(_OPENSSH_FOOTER).split())
    try:
        raw = base64.b64decode(body, validate=True)
    except ValueError:
        raise SshKeyError("unsupported_format") from None
    if not raw.startswith(_OPENSSH_MAGIC):
        raise SshKeyError("unsupported_format")
    pos = len(_OPENSSH_MAGIC)
    cipher, pos = _read_string(raw, pos)
    _kdf, pos = _read_string(raw, pos)
    _opts, pos = _read_string(raw, pos)
    if pos + 4 > len(raw) or struct.unpack_from(">I", raw, pos)[0] != 1:
        raise SshKeyError("unsupported_format")
    public, _pos = _read_string(raw, pos + 4)
    key_type, _rest = _read_string(public, 0)
    return key_type.decode("ascii", "replace"), cipher != b"none"


def load_private_key(text: str, passphrase: str | None) -> AgentKey:
    stripped = text.strip() if isinstance(text, str) else ""
    password = passphrase.encode("utf-8") if passphrase else None
    if stripped.startswith(_OPENSSH_HEADER):
        key_type, encrypted = _openssh_container(stripped)
        if key_type not in ("ssh-ed25519", "ssh-rsa", *(v[0] for v in _CURVES.values())):
            raise SshKeyError("unsupported_format")  # sk-*, DSA, certificates
        if encrypted and password is None:
            raise SshKeyError("needs_passphrase")
        if not encrypted:
            password = None  # a stored passphrase may be filled for an unencrypted key
        loader: Any = serialization.load_ssh_private_key
    elif stripped.startswith(_PEM_HEADERS):
        if stripped.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----") or "Proc-Type: 4,ENCRYPTED" in stripped[:512]:
            if password is None:
                raise SshKeyError("needs_passphrase")
        else:
            password = None
        loader = serialization.load_pem_private_key
    else:
        raise SshKeyError("unsupported_format")
    try:
        private = loader((stripped + "\n").encode("utf-8"), password)
    except UnsupportedAlgorithm:
        raise SshKeyError("unsupported_format") from None
    except (ValueError, TypeError):
        raise SshKeyError("bad_passphrase" if password is not None else "unsupported_format") from None
    return _agent_key(private)


def generate_ed25519(comment: str) -> tuple[str, str]:
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode("ascii")
    return pem, _agent_key(private).public_line(comment)
