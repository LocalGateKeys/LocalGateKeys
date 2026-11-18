"""Duress vault (sub-plan 08, Task 4): a second master password that opens a separate, plausible vault.

The second vault is an ordinary vault in its own folder inside the profile (``.lgk-d/vault.json``) with its own
master password, documents (``Attachments``) and backups, so the app behaves exactly as with any vault once it
is open and nothing it writes touches the real vault's files (the app's profile paths point into that folder
while it is open, see ``app.controller``).  The unlock screen tries the real vault first and this one second
(``open_vault``); a wrong password gets the same error text either way.

Timing: when the second vault exists, **both** Argon2id derivations run on every master-password unlock,
whichever password matched (or none), so the time taken does not tell which vault opened.  Without one, a
single derivation runs (Ruling T4: the second vault is visible on disk anyway, so slowing every unlock would
hide nothing).  While the real vault is held (below) its password is still put through the same Argon2id work
and then refused with the wrong-password text.

The real master password is kept apart from the duress password: setup refuses one equal or one edit away, and
a later change of the real password is checked against a keyed fingerprint of the duress password's one-edit
neighbourhood kept inside the encrypted real vault (``check_new_master``), plus an exact try of the second vault.

Opening the second vault holds the real vault for ``lock_hours`` (``trip``): a local file records until when
(with a copy outside the vault folder and a monotonic-clock anchor, see ``held_until``), and during that time the real master password, Windows Hello, the camera, the security key and the recovery
phrase are all refused as if wrong.  If the device was in a cloud-folder sync group when the duress password
was set up, a signed marker is also written to that folder (``mark_tripped``) and the owner's other devices
show "Duress password used on <device> at <time>" (``read_markers``).

A session opened here carries ``decoy = True``, ``sync_enabled = False`` and ``browser_enabled = False``:
the app starts no sync, serves no browser extension, SSH agent, command line or Windows passkey request,
runs no emergency access timer and writes no heir or scheduled backup for it.  The flag never reaches the
page.  What this protects and what it does not is in ``SECURITY.md`` ("Duress vault").
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import time
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import envelope, outside_marks
from . import vault as _vault
from .config import atomic_write_json
from .i18n import t
from .secret_text import SecretText, as_secret, secrets_match
from .vault import (
    InvalidMasterPassword,
    UnlockThrottle,
    VaultError,
    VaultSession,
    create_vault,
    require_pro_feature,
    unlock_vault,
)

__all__ = [
    "FEATURE", "DECOY_DIR", "MIN_LOCK_HOURS", "MAX_LOCK_HOURS", "DEFAULT_LOCK_HOURS", "MAX_COPIED_ITEMS",
    "DuressError", "MarkerIdentity", "Marker", "decoy_path", "hold_path", "configured", "is_decoy",
    "within_one_edit", "setup", "remove", "try_open", "open_vault", "real_held", "held_until", "trip",
    "release", "lock_hours", "marker_identity", "mark_tripped", "read_markers", "copy_candidates",
    "refuse_recovery", "decoy_dir", "real_path_of", "migrate_old_layout", "check_new_master", "shown_path",
]

#: The Pro feature (``licensing.Feature.DURESS``).
FEATURE = "duress"
DECOY_DIR = ".lgk-d"
HOLD_SUFFIX = ".hold.json"
#: ``outside_marks`` purpose of the hold copy kept outside the vault folder.
_HOLD_MARK_PURPOSE = "duress-hold"
_HOLD_ID_MARK_PURPOSE = "duress-hold-id"
#: Files of the first layout (the second vault beside the real one); removed on sight, never released.
_OLD_SUFFIXES = (".decoy", ".decoy.lock", ".decoy-hold")
_OLD_SIDECARS = ("vault.json.unlock-throttle.json", "vault.json.unlock-throttle.key", "vault.json.generation.json")
#: Passwords longer than this keep only the exact checks (the fingerprint holds 2n+1 hashes).
NEAR_LIMIT = 256
MIN_LOCK_HOURS = 1
MAX_LOCK_HOURS = 168
DEFAULT_LOCK_HOURS = 24
MAX_COPIED_ITEMS = 10
#: Real vault preference: ``{"hours": int, "created": int}`` (never synced; ``vault_bridge`` syncs named keys only).
REAL_PREF = "duress"
#: Second vault preference: ``{"hours": int}`` plus the marker identity when a sync folder was configured.
DECOY_PREF = "device_alert"
MARKER_FORMAT = "lgkalert"
MARKER_VERSION = 1
MARKER_DIR = "alerts"
MARKER_SUFFIX = ".lgkalert"
MARKER_LIMIT = 4096
#: Markers older than this are not shown any more.
MARKER_MAX_AGE = 14 * 24 * 3600
_ENDORSE_CONTEXT = b"localgatekeys|duress|marker-key|v1|"
_SYNC_DIR_NAME = "LocalGateKeys Sync"  # folder_transport.SYNC_DIR_NAME (not imported: no sync import at unlock)


class DuressError(ValueError):
    """``code``: ``same`` / ``close`` (too near the master password), ``near_duress`` (a new master password too
    near the duress password), ``mismatch``, ``hours``, ``exists``, ``missing`` or ``generic`` (the plain
    "couldn't save" that every refusal inside a duress session ends with)."""

    MESSAGES = {
        "same": "duress.err.same",
        "close": "duress.err.close",
        "near_duress": "duress.err.nearDuress",
        "mismatch": "duress.err.mismatch",
        "hours": "duress.err.hours",
        "exists": "duress.err.exists",
        "missing": "duress.err.missing",
        "generic": "duress.err.generic",
    }

    def __init__(self, code: str) -> None:
        super().__init__(t(self.MESSAGES.get(code, "duress.err.generic"), min=MIN_LOCK_HOURS,
                           max=MAX_LOCK_HOURS))
        self.code = code


# ------------------------------------------------------------------------------------------------ paths
def decoy_dir(real_path: Path | str) -> Path:
    """The second vault's own folder: its documents, backups and other per-profile files live here."""
    return Path(real_path).parent / DECOY_DIR


def decoy_path(real_path: Path | str) -> Path:
    return decoy_dir(real_path) / "vault.json"


def hold_path(real_path: Path | str) -> Path:
    real_path = Path(real_path)
    return real_path.with_name(real_path.stem + HOLD_SUFFIX)


def real_path_of(session: Any) -> Path:
    """The real vault beside a duress session's own folder."""
    return Path(session.path).parent.parent / "vault.json"


def shown_path(path: Path | str) -> Path:
    """A path as the page may show it: inside the second vault's folder, the real profile's equivalent
    (display only; the files themselves stay where they are)."""
    path = Path(path)
    if DECOY_DIR not in path.parts:
        return path
    return Path(*[part for part in path.parts if part != DECOY_DIR])


def migrate_old_layout(real_path: Path | str) -> None:
    """Delete a second vault of the first (unreleased) layout, kept beside the real vault, and its files."""
    real_path = Path(real_path)
    for path in [real_path.with_name(real_path.name + suffix) for suffix in _OLD_SUFFIXES] + [
            real_path.with_name(name) for name in _OLD_SIDECARS]:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # Best-effort file/OS step: failure is harmless here, so it is ignored.
            pass


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def configured(real_path: Path | str) -> bool:
    """Whether a duress password is set up for the vault at ``real_path``."""
    migrate_old_layout(real_path)
    return _is_file(decoy_path(real_path))


def is_decoy(session: Any) -> bool:
    """Whether ``session`` was opened with the duress password (services check this, never the page)."""
    return getattr(session, "decoy", False) is True


def lock_hours(session: Any) -> int | None:
    """The hold time recorded in a real vault with a duress password, else None."""
    prefs = session._read_prefs()
    value = prefs.get(REAL_PREF)
    hours = value.get("hours") if isinstance(value, dict) else None
    return hours if type(hours) is int and MIN_LOCK_HOURS <= hours <= MAX_LOCK_HOURS else None


# ----------------------------------------------------------------------------------- password distance
def _code_points(secret: SecretText) -> list[int]:
    """The secret's code points, read from its UTF-8 buffer (``SecretText.from_str`` made it valid UTF-8)
    without making an unwipeable ``str``."""
    data = secret.buffer
    out: list[int] = []
    i, n = 0, len(data)
    while i < n:
        lead = data[i]
        size = 1 if lead < 0x80 else 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
        value = lead if size == 1 else lead & (0x3F >> (size - 1))
        for j in range(i + 1, min(i + size, n)):
            value = (value << 6) | (data[j] & 0x3F)
        out.append(value)
        i += size
    return out


def within_one_edit(first: str | SecretText, second: str | SecretText) -> bool:
    """Whether the two passwords are equal or one insertion, deletion or substitution apart (Levenshtein <= 1)."""
    a_secret, a_owned = as_secret(first)
    b_secret, b_owned = as_secret(second)
    a: list[int] = []
    b: list[int] = []
    try:
        a, b = _code_points(a_secret), _code_points(b_secret)
        if len(a) < len(b):
            a, b = b, a
        if len(a) - len(b) > 1:
            return False
        i = 0
        while i < len(b) and a[i] == b[i]:
            i += 1
        if len(a) == len(b):
            return a[i + 1:] == b[i + 1:]
        return a[i + 1:] == b[i:]
    finally:
        a.clear()
        b.clear()
        if a_owned:
            a_secret.wipe()
        if b_owned:
            b_secret.wipe()


# ------------------------------------------------------------------------------------------ markers
def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _endorse_message(group_id: str, device_id: str, marker_public: bytes) -> bytes:
    return _ENDORSE_CONTEXT + group_id.encode("utf-8") + b"|" + device_id.encode("utf-8") + b"|" + marker_public


@dataclass(frozen=True)
class MarkerIdentity:
    """The key a duress session signs its marker with, endorsed by the device's sync signing key at setup.

    Only this key (never the device's sync key) is kept in the second vault: someone who learns the duress
    password can at most forge a marker, not a sync view.
    """

    device_id: str
    group_id: str
    folder: str
    signing_key: ed25519.Ed25519PrivateKey
    endorsement: bytes

    @property
    def public(self) -> bytes:
        return self.signing_key.public_key().public_bytes_raw()

    @classmethod
    def create(cls, device_identity: Any, group_id: str, folder: str) -> MarkerIdentity:
        """From the device's sync identity (``sync.pairing.DeviceIdentity``) in the real session."""
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes_raw()
        device_id = str(device_identity.device_id)
        endorsement = device_identity.signing_key.sign(_endorse_message(group_id, device_id, public))
        return cls(device_id, str(group_id), str(folder), key, endorsement)

    def to_record(self) -> dict[str, str]:
        return {"device": self.device_id, "group": self.group_id, "folder": self.folder,
                "key": envelope.b64e(self.signing_key.private_bytes_raw()),
                "endorsement": envelope.b64e(self.endorsement)}

    @classmethod
    def from_record(cls, value: Any) -> MarkerIdentity | None:
        try:
            if not isinstance(value, dict):
                return None
            device, group, folder = value["device"], value["group"], value["folder"]
            if not all(isinstance(v, str) and 0 < len(v) <= 4096 for v in (device, group, folder)):
                return None
            key = ed25519.Ed25519PrivateKey.from_private_bytes(envelope.b64d(value["key"], 32))
            return cls(device, group, folder, key, envelope.b64d(value["endorsement"], 64))
        except (KeyError, ValueError, envelope.EnvelopeError):
            return None


@dataclass(frozen=True)
class Marker:
    device_id: str
    time: int


def _marker_dir(folder: Path | str) -> Path:
    return Path(folder) / _SYNC_DIR_NAME / MARKER_DIR


def mark_tripped(folder: Path | str | None, identity: MarkerIdentity | None, *, now: float | None = None) -> Path | None:
    """Write this device's signed marker to the sync folder; None (nothing written) without a usable folder.

    The folder itself must already exist: a disconnected drive never makes the app write somewhere else.
    """
    if identity is None or folder is None or not str(folder).strip():
        return None
    root = Path(folder)
    try:
        if not (root / _SYNC_DIR_NAME).is_dir():
            return None
        directory = _marker_dir(root)
        directory.mkdir(exist_ok=True)
        when = int(time.time() if now is None else now)
        payload = {"device": identity.device_id, "group": identity.group_id, "time": when,
                   "endorsement": envelope.b64e(identity.endorsement)}
        data = envelope.seal_signed(MARKER_FORMAT, MARKER_VERSION, package_id=str(uuid.uuid4()), sender="",
                                    payload=payload, signing_key=identity.signing_key)
        path = directory / (_sha(identity.device_id) + MARKER_SUFFIX)
        temp = directory / f".{path.name}.{secrets.token_hex(4)}.tmp"
        temp.write_bytes(data)
        os.replace(temp, path)
        return path
    except OSError:
        return None


def _public(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)) and len(value) == 32:
        return bytes(value)
    if isinstance(value, str):
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError:
            return None
        return raw if len(raw) == 32 else None
    return None


def read_markers(folder: Path | str | None, trusted: Mapping[str, Any], *, group_id: str,
                 exclude: Iterable[str] = (), now: float | None = None) -> list[Marker]:
    """The markers in ``folder`` signed by a key that a trusted device (``{device_id: Ed25519 public}``) endorsed.

    ``trusted`` comes from the reader's accepted keyring (member signing keys) and pinned view signers;
    markers of another group, of ``exclude`` (this device), from the future or older than ``MARKER_MAX_AGE``
    are skipped, as is anything malformed.
    """
    if folder is None or not str(folder).strip():
        return []
    directory = _marker_dir(folder)
    current = time.time() if now is None else now
    skip = set(exclude)
    out: list[Marker] = []
    try:
        names = sorted(entry.name for entry in os.scandir(directory) if entry.name.endswith(MARKER_SUFFIX))[:64]
    except OSError:
        return []
    for name in names:
        try:
            with (directory / name).open("rb") as handle:
                data = handle.read(MARKER_LIMIT + 1)
            sealed = envelope.open_signed(data, MARKER_FORMAT, MARKER_VERSION, limit=MARKER_LIMIT)
            payload = sealed.payload
            device, group, when = payload.get("device"), payload.get("group"), payload.get("time")
            if not isinstance(device, str) or group != group_id or type(when) is not int or device in skip:
                continue
            if name != _sha(device) + MARKER_SUFFIX or not current - MARKER_MAX_AGE <= when <= current + 300:
                continue
            key = _public(trusted.get(device))
            if key is None:
                continue
            endorsement = envelope.b64d(payload.get("endorsement"), 64)
            ed25519.Ed25519PublicKey.from_public_bytes(key).verify(
                endorsement, _endorse_message(group, device, sealed.signer))
        except (OSError, ValueError, InvalidSignature, envelope.EnvelopeError):
            continue
        out.append(Marker(device, when))
    return out


def marker_identity(session: Any) -> MarkerIdentity | None:
    """The marker identity kept in a duress session's vault (None when no folder was configured at setup)."""
    try:
        value = session._read_prefs().get(DECOY_PREF)
    except Exception:  # noqa: BLE001 - a locked or damaged session has none
        return None
    return MarkerIdentity.from_record(value.get("marker")) if isinstance(value, dict) else None


# ---------------------------------------------------------------------------------------------- hold
_BOOT_ID: list[str | None] = []


def _boot_id() -> str | None:
    """This boot's identifier, read once per process: Windows' ``BootId`` counter (HKLM, read only; a user
    cannot change it), Linux's ``boot_id``; None when unknown."""
    if not _BOOT_ID:
        value: str | None = None
        try:
            if sys.platform == "win32":
                import winreg

                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager"
                                    r"\Memory Management\PrefetchParameters") as key:
                    boot, kind = winreg.QueryValueEx(key, "BootId")
                value = f"win:{boot}" if kind == winreg.REG_DWORD else None
            else:
                value = "linux:" + Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except (OSError, ValueError):
            value = None
        _BOOT_ID.append(value)
    return _BOOT_ID[0]


def _tick_seconds() -> int:
    """Whole seconds on this boot's monotonic clock: ``GetTickCount64`` on Windows (sleep included, never moved by
    setting the date), else ``time.monotonic``."""
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            return int(kernel32.GetTickCount64() // 1000)
        except (OSError, AttributeError):
            pass
    return int(time.monotonic())


def _boot_clock() -> tuple[str | None, int]:
    """(boot id, monotonic seconds); patched by tests with a fake clock."""
    return _boot_id(), _tick_seconds()


def _monotonic_remaining(length: int, mono: int, boot: str | None, now_boot: str | None, now_seconds: int,
                         wall_elapsed: int) -> int:
    """Seconds of a hold of ``length`` still to run on the monotonic clock, anchored at ``mono`` in ``boot``.

    The count is never more than the time that really passed.  A clock below the anchor restarted: only the time
    since then counts.  On another boot whose clock is already past the anchor the time since that boot counts,
    capped by the wall clock (Fast Startup can carry the tick count across a shutdown), and never less than the
    count on the same clock.  So a restart can make the hold longer, never shorter (as on the iPhone).
    """
    if now_seconds < mono:
        counted = now_seconds
    elif boot is not None and now_boot is not None and boot != now_boot:
        counted = max(now_seconds - mono, min(now_seconds, wall_elapsed))
    else:
        counted = now_seconds - mono
    return length - max(counted, 0)


def _record_until(raw: Any, current: float) -> int:
    """Until when a parsed hold record holds; ValueError when it is malformed.

    Audit 2026-11-10: a record with its monotonic anchor (``mono``, ``boot``) ends only once the wall clock has
    passed ``until`` and the monotonic clock has also counted the hold's length (``until - since``), so moving the
    date forward does not end it.  A record an earlier release wrote (no anchor) uses the wall clock alone.
    """
    until = raw.get("until") if isinstance(raw, dict) else None
    if type(until) is not int:
        raise ValueError("hold record is malformed")
    since, mono, boot = raw.get("since"), raw.get("mono"), raw.get("boot")
    if type(since) is int and type(mono) is int and until > since:
        now_boot, now_seconds = _boot_clock()
        remaining = _monotonic_remaining(until - since, mono, boot if isinstance(boot, str) else None, now_boot,
                                         now_seconds, int(current) - since)
        if remaining > 0:
            return max(until, int(current) + remaining)
    return until


def _hold_mark(real_path: Path | str) -> str:
    """The copy of the hold record kept outside the vault folder (``outside_marks``), so deleting the file does not
    end the hold."""
    return outside_marks.name_for(_HOLD_MARK_PURPOSE, real_path)


def _hold_marks(real_path: Path | str) -> list[str]:
    """Every outside copy of the hold: by path, and (design decision 2026-11-12) by the real vault's id, so a copy
    of the folder opened from another path, with its hold file deleted, is still held."""
    names = [_hold_mark(real_path)]
    vault_id = _vault.header_vault_id(real_path)
    if vault_id is not None:
        names.append(outside_marks.name_for_id(_HOLD_ID_MARK_PURPOSE, vault_id))
    return names


def _read_mark_record(name: str) -> Any:
    try:
        raw = outside_marks.read(name)
        return json.loads(raw) if raw else None
    except (OSError, ValueError, RecursionError):
        return None


def _read_hold_marks(real_path: Path | str) -> list[Any]:
    """The parsed outside copies; one that is missing, unreadable or malformed is left out (the file decides)."""
    return [record for record in map(_read_mark_record, _hold_marks(real_path)) if record is not None]


def _read_hold_mark(real_path: Path | str) -> Any:
    """The first parsed outside copy, or None."""
    records = _read_hold_marks(real_path)
    return records[0] if records else None


def _file_held_until(path: Path, current: float) -> int | None:
    try:
        if not path.exists():
            return None
        try:
            until = _record_until(json.loads(path.read_bytes()[:4096]), current)
        except (ValueError, RecursionError):
            until = int(path.stat().st_mtime) + MAX_LOCK_HOURS * 3600
    except OSError:
        return int(current) + 60  # cannot even look: fail closed for a minute
    return until if until > current else None


def _mark_held_until(real_path: Path | str, current: float) -> int | None:
    found = []
    for record in _read_hold_marks(real_path):
        try:
            found.append(_record_until(record, current))
        except ValueError:
            continue
    until = max(found) if found else None
    return until if until is not None and until > current else None


def held_until(real_path: Path | str, *, now: float | None = None) -> int | None:
    """Until when (epoch seconds) the real vault is held, or None when it is not.

    Held when either copy says so: the hold file next to the vault or its copy outside the vault folder.  An
    unreadable hold file fails closed for ``MAX_LOCK_HOURS`` after it was last written; a missing or unreadable
    outside copy leaves the decision to the file.
    """
    current = time.time() if now is None else now
    found = [until for until in (_file_held_until(hold_path(real_path), current),
                                 _mark_held_until(real_path, current)) if until is not None]
    return max(found) if found else None


def real_held(real_path: Path | str, now: float | None = None) -> bool:
    return held_until(real_path, now=now) is not None


def _decoy_hours(session: Any) -> int:
    try:
        value = session._read_prefs().get(DECOY_PREF)
    except Exception:  # noqa: BLE001
        value = None
    hours = value.get("hours") if isinstance(value, dict) else None
    return hours if type(hours) is int and MIN_LOCK_HOURS <= hours <= MAX_LOCK_HOURS else DEFAULT_LOCK_HOURS


def trip(real_path: Path | str, session: Any, *, now: float | None = None) -> int:
    """Hold the real vault after a duress unlock; returns until when.  Never shortens an earlier hold."""
    current = int(time.time() if now is None else now)
    until = current + _decoy_hours(session) * 3600
    earlier = held_until(real_path, now=current)
    if earlier is not None:
        until = max(until, earlier)
    boot, mono = _boot_clock()
    record: dict[str, Any] = {"version": 1, "since": current, "until": until, "mono": mono}
    if boot is not None:
        record["boot"] = boot
    # The outside copy first, so a hold file that cannot be written (this raises) still leaves a hold.
    for name in _hold_marks(real_path):
        outside_marks.write(name, json.dumps(record, separators=(",", ":")))
    atomic_write_json(hold_path(real_path), record)
    return until


def release(real_path: Path | str, *, now: float | None = None) -> int | None:
    """After a real unlock: remove a finished hold (both copies); returns when the duress password was used
    (else None)."""
    path = hold_path(real_path)
    mark = _read_hold_mark(real_path)
    try:
        has_file = path.exists()
        if (not has_file and mark is None) or held_until(real_path, now=now) is not None:
            return None
        since = None
        if has_file:
            try:
                raw = json.loads(path.read_bytes()[:4096])
                since = raw.get("since") if isinstance(raw, dict) else None
            except (ValueError, RecursionError):
                since = None
        if type(since) is not int and isinstance(mark, dict):
            since = mark.get("since")
        path.unlink(missing_ok=True)
    except OSError:
        return None
    for name in _hold_marks(real_path):
        outside_marks.delete(name)
    return since if type(since) is int else 0


# --------------------------------------------------------------------------------------- unlocking
def _mark(session: VaultSession) -> VaultSession:
    session.decoy = True  # type: ignore[attr-defined]
    session.sync_enabled = False  # type: ignore[attr-defined]
    session.browser_enabled = False  # type: ignore[attr-defined]
    return session


def try_open(path: Path | str, password: str | SecretText, *, backup_count: int = 0) -> VaultSession | None:
    """Open the second vault at ``path`` with ``password``; None for a wrong password or an unusable file.

    No unlock throttle of its own: the real vault's counts every attempt (``open_vault``).  Its rolling
    backups go to its own folder's ``Backups``; no envelope or KDF upgrade.
    """
    path = Path(path)
    secret, owned = as_secret(password)
    try:
        header, source = _vault._read_vault_header(path)
        if _vault._header_factor_specs(header):
            return None
        backups = path.parent / "Backups" if backup_count else None
        session = _vault._open_with_password(path, header, source, secret, backup_dir=backups,
                                             backup_count=backup_count)
    except (InvalidMasterPassword, VaultError, OSError):
        return None
    finally:
        if owned:
            secret.wipe()
    return _mark(session)


def _probe_held(path: Path, secret: SecretText, factors: Any) -> None:
    """The real vault while it is held: the same reads, factor checks and Argon2id work as a real attempt,
    and always the wrong-password refusal (its own message for an empty or too long password)."""
    _vault._recover_vault_migration(path)
    header, _source = _vault._read_vault_header(path)
    specs = _vault._header_factor_specs(header)
    factor_secrets = _vault._resolve_factor_secrets(specs, factors)
    try:
        if _vault._has_wrapped_key(header):
            _vault._zero(_vault._unwrap_password_wrapper(header, secret, factor_secrets))
        else:
            _vault._zero(_vault._derive_key(secret, header["kdf"]))
    finally:
        _vault._zero_all(factor_secrets)
    raise InvalidMasterPassword(t("vault.err.wrongPasswordOrModified"))


def refuse_recovery(path: Path | str, phrase: str) -> None:
    """The recovery phrase while the real vault is held: the same throttle, checks and work as a real attempt
    (``unlock_with_recovery_phrase``), then always its wrong-phrase refusal.  Never returns."""
    path = Path(path)
    throttle = UnlockThrottle(path)
    throttle.check()
    entropy = _vault.entropy_from_phrase(phrase)
    header, _source = _vault._read_vault_header(path)
    wrapper = header.get("wrappers", {}).get("recovery") if _vault._has_wrapped_key(header) else None
    if not isinstance(wrapper, dict):
        raise _vault.RecoveryPhraseError(t("vault.err.noRecoveryPhrase"))
    try:
        _vault._zero(_vault._unwrap_recovery_wrapper(header, wrapper, entropy))
    except _vault.RecoveryPhraseError:
        # Expected failure for this optional step: fall back to the default behaviour.
        pass
    throttle.record_failure()
    raise _vault.RecoveryPhraseError(t("vault.err.recoveryWrongVault"))


def open_vault(path: Path | str, password: str | SecretText, *, factors: Any = None, backup_dir: Path | None = None,
               backup_count: int = 0, upgrade_kdf: bool = False, now: float | None = None) -> VaultSession:
    """The unlock screen's master-password unlock: the real vault first, then the second vault, equal work.

    Returns the real session, or a duress session (``is_decoy``).  Raises exactly what ``unlock_vault``
    raises for the real vault; a password that opens neither gets the real vault's wrong-password error.
    Without a second vault (and no hold) this is ``unlock_vault`` itself.
    """
    path = Path(path)
    migrate_old_layout(path)
    second = decoy_path(path)
    has_second = _is_file(second)
    held = real_held(path, now)
    if not (has_second or held):
        return unlock_vault(path, password, factors=factors, backup_dir=backup_dir, backup_count=backup_count,
                            upgrade_kdf=upgrade_kdf)
    secret, owned = as_secret(password)
    try:
        throttle = UnlockThrottle(path)
        throttle.check()
        real: VaultSession | None = None
        failure: InvalidMasterPassword | None = None
        factor_error: Exception | None = None
        if held:
            try:
                _probe_held(path, secret, factors)
            except InvalidMasterPassword as exc:
                throttle.record_failure()
                failure = exc
        else:
            try:
                real = unlock_vault(path, secret, factors=factors, backup_dir=backup_dir,
                                    backup_count=backup_count, upgrade_kdf=upgrade_kdf)
            except InvalidMasterPassword as exc:  # counted by unlock_vault
                failure = exc
            except (_vault.FactorRequired, _vault.FactorMismatch) as exc:
                # The real vault wants its security key; the second vault must
                # still open with its own password while the key is absent.
                # Defensive: unreachable today (no hold means a second vault exists), kept in case that changes.
                if not has_second:
                    raise
                factor_error = exc
        opened = try_open(second, secret, backup_count=backup_count) if has_second else None
        if real is not None:
            if opened is not None:
                opened.lock()
            return real
        if opened is not None:
            throttle.reset()
            return opened
        if factor_error is not None:
            # Not counted (W-L13), as ``unlock_vault`` does not count it: without the key the real
            # password cannot be told from a wrong one, so counting would lock out the owner who
            # typed the right password and forgot the key.  The real vault cannot be guessed
            # without its key, and a missing key now looks the same with or without a second vault.
            raise factor_error
        raise failure or InvalidMasterPassword(t("vault.err.wrongPasswordOrModified"))
    finally:
        if owned:
            secret.wipe()


# ------------------------------------------------------------------------ the one-edit fingerprint
def _utf8(points: Sequence[int]) -> bytes:
    return "".join(chr(p) for p in points).encode("utf-8", "surrogatepass")


def _near_hashes(key: bytes, secret: SecretText) -> tuple[bytes, set[bytes], set[bytes]]:
    """``(whole, deletions, positional)``: keyed hashes of the password, of each one-character deletion and of
    each deletion with its position.  Two passwords are at most one edit apart exactly when their ``whole`` is
    equal, one's ``whole`` is in the other's ``deletions`` (an insertion or deletion), or their ``positional``
    sets meet (a substitution)."""
    def mac(tag: bytes, data: bytes) -> bytes:
        return hmac.new(key, tag + data, hashlib.sha256).digest()[:16]

    points = _code_points(secret)
    try:
        whole = mac(b"U|", _utf8(points))
        deletions: set[bytes] = set()
        positional: set[bytes] = set()
        for i in range(len(points)):
            rest = _utf8(points[:i] + points[i + 1:])
            deletions.add(mac(b"U|", rest))
            positional.add(mac(f"P{i}|".encode(), rest))
        return whole, deletions, positional
    finally:
        points.clear()


def _near_record(secret: SecretText) -> dict[str, Any] | None:
    if secret.char_count > NEAR_LIMIT:
        return None
    key = os.urandom(32)
    whole, deletions, positional = _near_hashes(key, secret)
    return {"key": envelope.b64e(key), "whole": envelope.b64e(whole),
            "deletions": sorted(envelope.b64e(h) for h in deletions),
            "positional": sorted(envelope.b64e(h) for h in positional)}


def _near(record: Any, secret: SecretText) -> bool:
    """Whether ``secret`` is the fingerprinted password or one edit away from it."""
    try:
        key = envelope.b64d(record["key"], 32)
        whole = envelope.b64d(record["whole"], 16)
        deletions = {envelope.b64d(v, 16) for v in record["deletions"]}
        positional = {envelope.b64d(v, 16) for v in record["positional"]}
    except (KeyError, TypeError, envelope.EnvelopeError):
        return False
    if secret.char_count > NEAR_LIMIT + 1:
        return False
    mine, my_deletions, my_positional = _near_hashes(key, secret)
    return (hmac.compare_digest(mine, whole) or mine in deletions or whole in my_deletions
            or bool(positional & my_positional))


def check_new_master(session: Any, new_password: str | SecretText) -> None:
    """Before a master-password change (or a reset with the recovery phrase) of ``session``'s vault.

    Real vault with a duress password: refuses the duress password and anything one edit away from it
    (``near_duress``), from the fingerprint kept at setup and, in case the duress password changed since, an
    exact try of the second vault.  A duress session checks nothing: trying a candidate against the real vault
    from there would be a password oracle during the hold and would fill the real vault's throttle with every
    ordinary change (review R2).  The real-first unlock order still lets the real vault win if they ever match.
    """
    if is_decoy(session):
        return
    secret, owned = as_secret(new_password)
    try:
        if not configured(session.path):
            return
        record = session._read_prefs().get(REAL_PREF)
        if isinstance(record, dict) and _near(record.get("near"), secret):
            raise DuressError("near_duress")
        opened = try_open(decoy_path(session.path), secret)
        if opened is not None:
            opened.lock()
            raise DuressError("near_duress")
    finally:
        if owned:
            secret.wipe()


# ------------------------------------------------------------------------------------------- setup
def copy_candidates(session: Any) -> list[dict[str, str]]:
    """Items the user may copy into the second vault: website logins, notes and bookmarks (titles only)."""
    out: list[dict[str, str]] = []
    for summary in session.summaries():
        if summary.kind == "web":
            out.append({"id": summary.id, "title": summary.label, "kind": "login"})
    for item in session.item_service.list_items(kinds={"note", "bookmark"}):
        out.append({"id": str(item.get("id", "")), "title": str(item.get("title") or ""),
                    "kind": str(item.get("kind") or "")})
    return out


def _copy_items(real: Any, second: Any, item_ids: Sequence[str]) -> int:
    copied = 0
    typed = second.item_service
    for item_id in list(dict.fromkeys(item_ids))[:MAX_COPIED_ITEMS]:
        entry = real.get_entry(item_id)
        if entry is not None:
            if entry.get("kind") == "web" and entry.get("password"):
                second.upsert_web(origin=str(entry.get("scope", {}).get("origin", "")),
                                  username=str(entry.get("username") or ""), password=str(entry["password"]),
                                  label=str(entry.get("label") or "") or None)
                copied += 1
            continue
        item = real.item_service.get_item(item_id, include_protected=True)
        if not item:
            continue
        payload = item.get("payload") or {}
        if item.get("kind") == "note":
            typed.create_note(str(item.get("title") or ""), str(payload.get("body") or ""))
            copied += 1
        elif item.get("kind") == "bookmark":
            typed.create_bookmark(str(item.get("title") or ""), str(payload.get("url") or ""),
                                  notes=str(payload.get("notes") or ""))
            copied += 1
    return copied


def _sample_password() -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))


def _sample_items(real: Any, second: Any) -> None:
    """A few plausible items: the owner's most used user name on two common sites, two notes, two bookmarks."""
    names = Counter(s.username for s in real.summaries() if s.kind == "web" and s.username)
    username = names.most_common(1)[0][0] if names else ""
    for origin in ("https://www.wikipedia.org", "https://www.amazon.com"):
        second.upsert_web(origin=origin, username=username, password=_sample_password())
    typed = second.item_service
    typed.create_note(t("duress.sample.shoppingTitle"), t("duress.sample.shoppingBody"))
    typed.create_note(t("duress.sample.bikeTitle"), t("duress.sample.bikeBody", code=f"{secrets.randbelow(10000):04d}"))
    typed.create_bookmark(t("duress.sample.weather"), "https://www.accuweather.com/")
    typed.create_bookmark(t("duress.sample.news"), "https://www.bbc.com/news")


def _check_hours(hours: Any) -> int:
    if type(hours) is not int or not MIN_LOCK_HOURS <= hours <= MAX_LOCK_HOURS:
        raise DuressError("hours")
    return hours


def setup(session: Any, decoy_password: str | SecretText, *, lock_hours: int, master_password: str | SecretText,
          items: Sequence[str] = (), marker: MarkerIdentity | None = None) -> Path:
    """Create the second vault for the real ``session``; returns its path.

    ``master_password`` is the real one, checked here (and needed to refuse a duress password equal to it or
    one edit away).  ``items`` are ids from ``copy_candidates`` (at most ``MAX_COPIED_ITEMS`` are copied);
    without any, plausible sample items are made.  ``marker`` (from the device's sync identity, when a
    cloud folder is configured) is kept in the second vault so a duress unlock can sign its marker.
    """
    require_pro_feature(session, FEATURE)
    hours = _check_hours(lock_hours)
    session.verify_master_password(master_password)
    if within_one_edit(master_password, decoy_password):
        raise DuressError("same" if secrets_match(master_password, decoy_password) else "close")
    if is_decoy(session):
        # Inside a duress session every check above runs as usual, then the plain "couldn't save": nothing is
        # written, and nothing says why (Ruling T4b).
        raise DuressError("generic")
    path = decoy_path(session.path)
    migrate_old_layout(session.path)
    if _is_file(path):
        raise DuressError("exists")
    # Leftovers of an earlier second vault (a rollback record above generation 1 would refuse the new one).
    _remove_files(session.path)
    kdf = session._header.get("kdf", {})
    overrides = {k: int(kdf[k]) for k in ("time_cost", "memory_cost_kib", "parallelism", "hash_len") if k in kdf}
    path.parent.mkdir(exist_ok=True)
    second = create_vault(path, decoy_password, kdf_overrides=overrides or None)
    try:
        if not _copy_items(session, second, items):
            _sample_items(session, second)
        record: dict[str, Any] = {"hours": hours}
        if marker is not None:
            record["marker"] = marker.to_record()
        second._commit_prefs({DECOY_PREF: record})
        decoy_secret, decoy_owned = as_secret(decoy_password)
        try:
            near = _near_record(decoy_secret)
        finally:
            if decoy_owned:
                decoy_secret.wipe()
        real_record: dict[str, Any] = {"hours": hours, "created": int(time.time())}
        if near is not None:
            real_record["near"] = near
        session._commit_prefs({REAL_PREF: real_record})
    except BaseException:
        second.lock()
        _remove_files(session.path)
        raise
    second.lock()
    return path


def _remove_files(real_path: Path | str) -> None:
    """Delete the second vault's whole folder (its vault, documents, backups and sidecars), and first its
    rollback marks kept outside the folder, so nothing left there says a second vault existed."""
    from .vault import forget_rollback_marks

    try:
        forget_rollback_marks(decoy_path(real_path))
    except Exception:  # noqa: BLE001 - best effort, like the marks themselves
        pass
    shutil.rmtree(decoy_dir(real_path), ignore_errors=True)


def remove(session: Any) -> bool:
    """Remove the second vault (from the real session; Pro is not needed to remove).  False when none."""
    if is_decoy(session):
        raise DuressError("generic")
    existed = configured(session.path)
    _remove_files(session.path)
    try:
        hold_path(session.path).unlink(missing_ok=True)
    except OSError:
        # Best-effort file/OS step: failure is harmless here, so it is ignored.
        pass
    for name in _hold_marks(session.path):
        outside_marks.delete(name)
    if session._read_prefs().get(REAL_PREF) is not None:
        session._commit_prefs({REAL_PREF: None})
    return existed
