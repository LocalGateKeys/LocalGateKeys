from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import time
import uuid
import warnings
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import atomic_write_json, read_json
from .secret_text import SecretText, argon2id_raw, as_secret
from .vault import (
    DEFAULT_KDF,
    MAX_KDF_MEMORY_KIB,
    MIN_KDF_MEMORY_KIB,
    FactorMismatch,
    FactorRequired,
    FactorSecrets,
    RecoveryPhraseError,
)

# Vault-only .lgk envelope.  v2 authenticates the header (format, version, KDF
# parameters, cipher name and nonce) as associated data; v1 used a constant
# AAD and remains readable.
BACKUP_VERSION = 2
BACKUP_AAD = b"localgatekeys|encrypted-profile-backup|v1"
BACKUP_AAD_V2 = b"localgatekeys|encrypted-profile-backup|v2|"
SUPPORTED_BACKUP_VERSIONS = frozenset({1, 2})
# The encrypted inner payload layout did not change between envelope v1 and v2.
BACKUP_PAYLOAD_VERSION = 1

# Argon2id parameters for new backup/transfer writes mirror the vault default.
# Readers accept any header inside the vault's bounded range instead of a
# single hard-coded tuple so older and tuned files stay restorable.
BACKUP_KDF = {
    "name": "argon2id",
    "time_cost": int(DEFAULT_KDF["time_cost"]),
    "memory_cost_kib": int(DEFAULT_KDF["memory_cost_kib"]),
    "parallelism": int(DEFAULT_KDF["parallelism"]),
}
MIN_BACKUP_KDF_TIME_COST, MAX_BACKUP_KDF_TIME_COST = 1, 10
MIN_BACKUP_KDF_PARALLELISM, MAX_BACKUP_KDF_PARALLELISM = 1, 16
_KDF_FIELDS = ("time_cost", "memory_cost_kib", "parallelism")


class BackupError(Exception):
    pass


PRIVATE_TEMP_FOLDER = "tmp"


def private_temp_root() -> Path:
    """An owner-only ``tmp`` folder inside the data folder for scratch directories.

    ``tempfile.TemporaryDirectory`` in the shared system temp folder has a
    cleanup race on Windows (another process can swap the directory for a
    junction before rmtree runs).  Scratch directories are therefore created
    in a folder only the current user and SYSTEM can write to.  A link or
    junction in its place is refused rather than followed.
    """
    from .config import apply_owner_only_acl, data_dir, has_owner_only_acl
    root = data_dir() / PRIVATE_TEMP_FOLDER
    if root.is_symlink() or root.is_junction():
        raise OSError("The private temporary folder is a link")
    created = False
    if not root.is_dir():
        root.mkdir(mode=0o700)
        created = True
    if os.name == "nt":
        try:
            if created or not has_owner_only_acl(root):
                apply_owner_only_acl(root)
        except Exception:  # noqa: BLE001 - best-effort, like the data folder ACL
            import logging
            logging.getLogger(__name__).warning("Could not apply the owner-only ACL to the private temporary folder.")
    else:
        try:
            root.chmod(0o700)
        except OSError:
            pass
    return root


def private_temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """``TemporaryDirectory`` created inside ``private_temp_root()`` (still removed on exit)."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=private_temp_root())


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise BackupError("Backup contains invalid encoded data") from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _kdf_parameters(kdf: Any) -> dict[str, int | str]:
    """Bound Argon2id parameters before any derivation runs (fail closed)."""
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise BackupError("Unsupported backup encryption parameters")
    values: dict[str, int | str] = {"name": "argon2id"}
    for field in _KDF_FIELDS:
        value = kdf.get(field)
        if type(value) is not int:
            raise BackupError("Unsupported backup encryption parameters")
        values[field] = value
    if not (MIN_BACKUP_KDF_TIME_COST <= int(values["time_cost"]) <= MAX_BACKUP_KDF_TIME_COST
            and MIN_KDF_MEMORY_KIB <= int(values["memory_cost_kib"]) <= MAX_KDF_MEMORY_KIB
            and MIN_BACKUP_KDF_PARALLELISM <= int(values["parallelism"]) <= MAX_BACKUP_KDF_PARALLELISM):
        raise BackupError("Unsupported backup encryption parameters")
    if "hash_len" in kdf and kdf.get("hash_len") != 32:
        raise BackupError("Unsupported backup encryption parameters")
    return values


def _new_kdf(kdf_overrides: dict[str, int] | None) -> dict[str, int | str]:
    kdf: dict[str, Any] = dict(BACKUP_KDF)
    if kdf_overrides:
        for field in _KDF_FIELDS:
            if field in kdf_overrides:
                kdf[field] = kdf_overrides[field]
    return _kdf_parameters(kdf)


def _derive(password: str | SecretText, salt: bytes, kdf: dict[str, Any]) -> bytes:
    """The backup key. A ``SecretText`` password is hashed straight from its wipeable buffer."""
    if isinstance(password, SecretText):
        try:
            length = password.char_count
        except ValueError:
            raise BackupError("Backup password must contain at least 12 characters") from None
    elif isinstance(password, str):
        length = len(password)
    else:
        length = 0
    if not 12 <= length <= 4096:
        raise BackupError("Backup password must contain at least 12 characters")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise BackupError("Malformed encryption header")
    parameters = _kdf_parameters(kdf)
    if isinstance(password, SecretText):
        key = argon2id_raw(password.buffer, salt, time_cost=int(parameters["time_cost"]),
                           memory_cost=int(parameters["memory_cost_kib"]),
                           parallelism=int(parameters["parallelism"]), hash_len=32)
        try:
            return bytes(key)
        finally:
            key[:] = b"\0" * len(key)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(parameters["time_cost"]),
        memory_cost=int(parameters["memory_cost_kib"]),
        parallelism=int(parameters["parallelism"]),
        hash_len=32,
        type=Type.ID,
    )


def _backup_header_aad(envelope: dict[str, Any]) -> bytes:
    return BACKUP_AAD_V2 + _canonical({
        "format": envelope["format"],
        "version": envelope["version"],
        "kdf": envelope["kdf"],
        "cipher": {"name": envelope["cipher"]["name"], "nonce": envelope["cipher"]["nonce"]},
    })


def export_encrypted_backup(
    destination: Path,
    *,
    vault_file: Path,
    settings_file: Path | None,
    profile_name: str,
    backup_password: str,
    kdf_overrides: dict[str, int] | None = None,
    vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> None:
    """``vault_filter``: what the vault file becomes in the backup (``without_share_records``)."""
    if not vault_file.exists():
        raise BackupError("There is no vault to back up yet")
    kdf = _new_kdf(kdf_overrides)
    vault = read_json(vault_file)
    payload: dict[str, Any] = {
        "version": BACKUP_PAYLOAD_VERSION,
        "exported_at": int(time.time()),
        "profile_name": profile_name,
        "vault": vault_filter(vault) if vault_filter is not None else vault,
        "settings": _without_language(read_json(settings_file)) if settings_file and settings_file.exists() else None,
    }
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    salt = os.urandom(16)
    key = _derive(backup_password, salt, kdf)
    nonce = os.urandom(12)
    envelope: dict[str, Any] = {
        "format": "localgatekeys-backup",
        "version": BACKUP_VERSION,
        "kdf": {**kdf, "salt": _b64e(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce": _b64e(nonce)},
    }
    envelope["cipher"]["ciphertext"] = _b64e(AESGCM(key).encrypt(nonce, plaintext, _backup_header_aad(envelope)))
    atomic_write_json(destination, envelope)


def _forget_removal_watch(vault_file: Path) -> None:
    """A restored vault must never be erased by an old removal notice: drop the watch file beside it."""
    from .sync import removal

    removal.forget_watch(removal.watch_path(vault_file))


def restore_encrypted_backup(
    source: Path,
    *,
    vault_file: Path,
    settings_file: Path | None,
    backup_password: str,
) -> str:
    warnings.warn(
        "restore_encrypted_backup is retained for compatibility; use restore_verified_backup for new restores",
        DeprecationWarning,
        stacklevel=2,
    )
    # Keep this compatibility API on the same bounded envelope parser as the
    # verified restore path. It still cannot verify the vault master password
    # because that password is intentionally not part of this API.
    payload = _read_backup_payload(source, backup_password)

    atomic_write_json(vault_file, payload["vault"])
    _forget_removal_watch(vault_file)
    # The rollback anchor is deliberately left alone: this API cannot open the
    # vault, so it cannot mint an authenticated anchor, and resetting it would
    # silently accept an older vault.  An older restored copy therefore fails
    # the rollback check at the next unlock until the user confirms a rollback
    # through the verified restore path.
    if settings_file is not None and isinstance(payload.get("settings"), dict):
        restored_settings = dict(payload["settings"])
        _keep_device_settings(restored_settings, _current_device_settings(settings_file))
        atomic_write_json(settings_file, restored_settings)
    return str(payload.get("profile_name") or "Restored profile")


MAX_BACKUP_BYTES = 32 * 1024 * 1024


def _read_backup_payload(source: Path, backup_password: str) -> dict[str, Any]:
    """Validate bounds before decryption; never create a plaintext temporary file."""
    try:
        if source.stat().st_size > MAX_BACKUP_BYTES:
            raise BackupError("Backup is too large")
        with source.open("rb") as handle:
            blob = handle.read(MAX_BACKUP_BYTES + 1)
        if len(blob) > MAX_BACKUP_BYTES:
            raise BackupError("Backup is too large")
        envelope = json.loads(blob)
        if not isinstance(envelope, dict):
            raise BackupError("Backup header must be an object")
        version = envelope.get("version")
        if envelope.get("format") != "localgatekeys-backup" or version not in SUPPORTED_BACKUP_VERSIONS:
            raise BackupError("Unsupported backup format")
        kdf, cipher = envelope["kdf"], envelope["cipher"]
        if not isinstance(kdf, dict) or not isinstance(cipher, dict) or cipher.get("name") != "aes-256-gcm":
            raise BackupError("Unsupported backup encryption parameters")
        _kdf_parameters(kdf)
        salt, nonce = _b64d(kdf["salt"]), _b64d(cipher["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise BackupError("Malformed encryption header")
        aad = BACKUP_AAD if version == 1 else _backup_header_aad(envelope)
        raw = AESGCM(_derive(backup_password, salt, kdf)).decrypt(nonce, _b64d(cipher["ciphertext"]), aad)
        payload = json.loads(raw)
        if (not isinstance(payload, dict) or payload.get("version") != BACKUP_PAYLOAD_VERSION or
                not isinstance(payload.get("vault"), dict)):
            raise BackupError("Malformed encrypted backup payload")
        return payload
    except InvalidTag:
        raise BackupError("Wrong backup password or modified backup") from None
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        raise BackupError("Could not read this backup") from None


def _vault_secret(value: Any, message: str) -> tuple[SecretText, bool]:
    """Convert the vault (master) password once at a public entry: ``(secret, owned)``."""
    if not isinstance(value, (str, SecretText)):
        raise BackupError(message)
    try:
        return as_secret(value)
    except ValueError:
        raise BackupError(message) from None


_VERIFY_FAILED = ("Backup opened, but its vault could not be unlocked/validated. "
                  "Use the vault master password from when this backup was made.")

# Raised while opening a backup's vault and passed up unchanged, never folded into "could not be unlocked":
# the UI asks for the key file / YubiKey of a v4 vault (FactorRequired), says which one is wrong
# (FactorMismatch), or says what is wrong with a recovery phrase.
VAULT_PROMPT_ERRORS = (FactorRequired, FactorMismatch, RecoveryPhraseError)


def _open_backup_vault(path: Path, vault_password: SecretText | None, *, factors: FactorSecrets | None = None,
                       recovery_phrase: str | None = None, upgrade_envelope: bool = True) -> Any:
    """Open a private copy of a backup's vault with its master password (+ factors) or its recovery phrase.

    A v4 vault whose factors were not supplied raises ``FactorRequired`` before its Argon2 runs; the error then
    carries ``specs``, the vault's public factor list (kinds and YubiKey slot, no secret), for the prompt.
    """
    from .vault import VaultError, unlock_vault, unlock_with_recovery_phrase, vault_factors

    if recovery_phrase is not None:
        return unlock_with_recovery_phrase(path, recovery_phrase)
    try:
        return unlock_vault(path, vault_password, factors=factors, upgrade_envelope=upgrade_envelope)
    except FactorRequired as exc:
        try:
            exc.specs = vault_factors(path)  # type: ignore[attr-defined]
        except (VaultError, OSError, ValueError):
            exc.specs = []  # type: ignore[attr-defined]
        raise


def _finish_phrase_restore(session: Any, new_password: SecretText) -> list[str]:
    """A recovery-phrase restore: ``new_password`` becomes the master password; returns the dropped factor kinds.

    As for a phrase reset of the live vault, a key file / YubiKey is removed (format 3 again): the phrase is what
    opens a vault whose factor was lost.
    """
    result = session.set_master_password_after_recovery(new_password)
    return [str(kind) for kind in result.get("factors_removed", [])]


def verify_encrypted_backup(source: Path, *, backup_password: str, vault_password: str | SecretText,
                            factors: FactorSecrets | None = None,
                            recovery_phrase: str | None = None) -> dict[str, Any]:
    """Verify BOTH layers of encryption and schema without touching a live vault.

    Existing .lgk exports wrap an already-encrypted vault. Consequently full
    recovery requires the backup password AND that vault's master password at
    the time the backup was made (plus its key file / YubiKey for a v4 vault,
    ``factors``; or its ``recovery_phrase`` instead of both). The temporary
    file below is encrypted only.
    """
    payload = _read_backup_payload(source, backup_password)
    secret, owned = _vault_secret(vault_password, _VERIFY_FAILED)
    try:
        return _verify_payload(payload, secret, factors=factors, recovery_phrase=recovery_phrase)
    finally:
        if owned:
            secret.wipe()


def _verify_payload(payload: dict[str, Any], vault_password: SecretText, *, factors: FactorSecrets | None = None,
                    recovery_phrase: str | None = None) -> dict[str, Any]:
    from .vault import VaultError
    try:
        # A private directory holds the encrypted copy and the anchor the
        # probe unlock writes; nothing is left behind in the system temp.  The
        # probe never upgrades a v1/v2 envelope, which would otherwise write a
        # migration journal and pre-migration snapshot beside the copy.
        with private_temporary_directory("lgk-verify-") as directory:
            encrypted_path = Path(directory) / "vault.json"
            atomic_write_json(encrypted_path, payload["vault"])
            session = _open_backup_vault(encrypted_path, vault_password, factors=factors,
                                         recovery_phrase=recovery_phrase, upgrade_envelope=False)
            try:
                return {"verified": True, "profile_name": str(payload.get("profile_name", "Restored profile")),
                        "entries": len(session.summaries()), "deleted_entries": len(session.trash_summaries()),
                        "exported_at": int(payload.get("exported_at", 0))}
            finally:
                session.lock()
    except VAULT_PROMPT_ERRORS:
        raise
    except (VaultError, OSError, ValueError, TypeError, OverflowError):
        raise BackupError("Backup opened, but its vault could not be unlocked/validated. Use the vault master password from when this backup was made.") from None


def _check_restore_rollback(session: Any, vault_file: Path, *, allow_rollback: bool) -> None:
    """Raise RollbackRequiresConfirmation when the destination already moved further ahead.

    The anchor is authenticated with the restored vault's data key.  An anchor
    that does not authenticate belongs to a different key lineage, which is
    also treated as a rollback that needs explicit confirmation.
    """
    from .vault import RollbackRequiresConfirmation, VaultError, _read_generation_anchor

    restored_generation = int(session._payload.get("generation", 0))
    try:
        current = session.rollback_anchor_generation(vault_file)
        foreign = False
    except VaultError:
        current, _upgrade = _read_generation_anchor(vault_file)
        foreign = True
    if current is None:
        return
    if (foreign or current > restored_generation) and not allow_rollback:
        raise RollbackRequiresConfirmation(current_generation=int(current), restored_generation=restored_generation)


def _without_language(settings: Any) -> Any:
    """Drop the per-device settings (language, developer pack) from an exported settings object."""
    if isinstance(settings, dict):
        return {k: v for k, v in settings.items() if k not in DEVICE_ONLY_SETTINGS}
    return settings


def _sanitize_restored_settings(settings: dict[str, Any]) -> None:
    """Autostart, external requests and automatic sign-in are OFF for a restored profile."""
    settings.update(start_with_windows=False, fill_and_sign_in=False, breach_check_enabled=False)


def _sanitize_restored_session(session: Any) -> None:
    """Restored credentials must not silently retain automatic sign-in or desktop-fill approvals."""
    from .access_policy import normalized_policy
    with session.transaction():
        session.set_fill_and_sign_in_enabled(False)
        for entry in session.all_entries():
            policy = normalized_policy(entry.get("policy"))
            policy["sign_in"] = "never"
            session.set_entry_extras(entry["id"], policy=policy)
            if entry["kind"] == "desktop":
                session.set_desktop_embedded_fill_approval(entry["id"], False)
            entry.clear()


# Shared collections (sub-plan 07, ruling F3).  A backup never carries a share: no share group (its keys,
# keyring, owner key and folder), no share bookkeeping, no share link and no "shared" mark on a collection.
# A restore keeps the shares the replaced vault has now instead, like the Mac (``MacFullBackup.keepingShared``):
# their records, their collections' rows and the items in them stay exactly as they are now.  Putting an older
# share record back would freeze the share for everyone (an owner record from before the share, or an epoch the
# group has left), and older shared items would be republished over other people's edits.
SHARE_PAYLOAD_KEYS = ("share_groups", "share_sync_meta", "collection_links")
# Device-only sync records a backup never carries and a restore never brings back: the identity this
# device kept when it left a sync group (``sync.vault_bridge.KEPT_IDENTITY_KEY``; not imported here, so
# a backup does not load the sync package).  Restored on another device it would be another device's id.
DEVICE_ONLY_PAYLOAD_KEYS = ("sync_rejoin",)
_DOCUMENT_KIND = "document"


def strip_share_records(payload: dict[str, Any]) -> None:
    """Take every share record (and every device-only sync record) out of a vault catalog (in place)."""
    for key in (*SHARE_PAYLOAD_KEYS, *DEVICE_ONLY_PAYLOAD_KEYS):
        payload.pop(key, None)
    for row in payload.get("collections") or []:
        if isinstance(row, dict):
            row.pop("shared_group_id", None)


def without_share_records(session: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """For a backup writer: the vault file (as read from disk) without its share records, sealed again with
    the unlocked ``session``'s key (``VaultSession.resealed``)."""
    from .vault import VaultError

    def strip(vault_json: dict[str, Any]) -> dict[str, Any]:
        try:
            resealed: dict[str, Any] = session.resealed(vault_json, strip_share_records)
        except VaultError as exc:
            raise BackupError("The vault changed while the backup was written; try again") from exc
        return resealed

    return strip


def _shared_collection_ids(current: dict[str, Any], rows: dict[str, dict[str, Any]]) -> set[str]:
    shared = {cid for cid, row in rows.items() if row.get("shared_group_id")}
    links = current.get("collection_links")
    if isinstance(links, dict):
        shared.update(cid for cid in links if isinstance(cid, str))
    groups = current.get("share_groups")
    if isinstance(groups, dict):
        shared.update(r["collection_id"] for r in groups.values()
                      if isinstance(r, dict) and isinstance(r.get("collection_id"), str))
    return shared & set(rows)


def keep_current_shares(payload: dict[str, Any], current: dict[str, Any] | None) -> None:
    """*payload* (a restored catalog) without the backup's share records and with *current*'s (the catalog
    being replaced; None when there is none or it does not open), in place.

    The collections shared now keep their current rows, and their items stay as they are now: an item in one
    of them now is put back as it is now, and a restored item that is not in it now leaves it (so nothing old
    is republished to the others).  Logins and documents never sync in a share and stay as restored.
    """
    strip_share_records(payload)
    rows = payload.get("collections")
    if not current or not isinstance(rows, list):
        return
    current_rows = {r["id"]: r for r in current.get("collections") or []
                    if isinstance(r, dict) and isinstance(r.get("id"), str)}
    shared = _shared_collection_ids(current, current_rows)
    for key in SHARE_PAYLOAD_KEYS:
        if key in current:
            payload[key] = copy.deepcopy(current[key])
    if not shared:
        return
    by_id = {r.get("id"): i for i, r in enumerate(rows) if isinstance(r, dict)}
    for cid in sorted(shared):
        row = copy.deepcopy(current_rows[cid])
        if cid in by_id:
            rows[by_id[cid]] = row
        else:
            rows.append(row)
    # A restored collection of another id may have the same name: the kept shared row gets a number, as a join does
    # (collection names are unique; re-review wave B, B2).
    from .sync.share_group import _unique_name

    for cid in sorted(shared):
        row = next(r for r in rows if isinstance(r, dict) and r.get("id") == cid)
        others = [r for r in rows if isinstance(r, dict) and r.get("id") != cid and isinstance(r.get("name"), str)]
        if isinstance(row.get("name"), str):
            row["name"] = _unique_name(row["name"], others)
    known = {r.get("id") for r in rows if isinstance(r, dict)}

    def in_shared(item: Any) -> bool:
        ids = item.get("collection_ids") if isinstance(item, dict) else None
        return isinstance(ids, list) and bool(shared.intersection(ids))

    def leave_shared(item: Any) -> None:
        ids = item.get("collection_ids") if isinstance(item, dict) else None
        if isinstance(ids, list) and item.get("kind") != _DOCUMENT_KIND:
            item["collection_ids"] = [c for c in ids if c not in shared]

    keep = {i["id"]: copy.deepcopy(i) for i in current.get("items") or []
            if in_shared(i) and isinstance(i.get("id"), str) and i.get("kind") != _DOCUMENT_KIND}
    for item in keep.values():
        item["collection_ids"] = [c for c in item["collection_ids"] if c in known]
    kept_ids = set(keep)
    items = payload.get("items")
    out: list[Any] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("id") in keep:
            out.append(keep.pop(item["id"]))
            continue
        leave_shared(item)
        out.append(item)
    out.extend(keep.values())
    payload["items"] = out
    trash = payload.get("trash")
    if isinstance(trash, list):
        restored_trash = []
        for record in trash:
            entry = record.get("entry") if isinstance(record, dict) else None
            if isinstance(entry, dict) and entry.get("id") in kept_ids:
                continue  # live again, as it is now
            leave_shared(entry)
            restored_trash.append(record)
        payload["trash"] = restored_trash


CURRENT_SHARES_UNREADABLE = (
    "The vault this restore replaces does not open with this master password, so its shared collections (and the "
    "signing key of a collection it shares) could not be kept. Restore with that vault's master password, or "
    "restore as a new profile.")


def _current_catalog(vault_file: Path | None, vault_password: SecretText | None, *,
                     factors: FactorSecrets | None = None, drop_current_shares: bool = False) -> dict[str, Any] | None:
    """What ``keep_current_shares`` needs of the vault a restore replaces, opened as a private copy (no unlock
    attempt counts against it); None when there is none.

    A replaced vault that does not open with the same master password and factors is refused (``BackupError``,
    re-review wave B, B2): whether it holds a share, an owner's signing key included, cannot be told without opening
    it, and dropping an owner's share freezes it for everyone. ``drop_current_shares`` (API only) accepts losing them.
    """
    from .vault import unlock_vault

    if vault_file is None or not vault_file.exists():
        return None
    if vault_password is None:
        if drop_current_shares:
            return None
        raise BackupError(CURRENT_SHARES_UNREADABLE)
    with private_temporary_directory("lgk-restore-current-") as directory:
        probe = Path(directory) / "vault.json"
        try:
            atomic_write_json(probe, read_json(vault_file))
            session = unlock_vault(probe, vault_password, factors=factors, upgrade_envelope=False)
        except Exception as exc:  # noqa: BLE001 - another password or a damaged file
            if drop_current_shares:
                return None
            raise BackupError(CURRENT_SHARES_UNREADABLE) from exc
        try:
            payload = session._require_payload()
            return copy.deepcopy({k: payload[k] for k in ("collections", "items", *SHARE_PAYLOAD_KEYS)
                                  if k in payload})
        finally:
            session.lock()


def _keep_current_shares_in(session: Any, current: dict[str, Any] | None) -> None:
    with session.transaction():
        keep_current_shares(session._require_payload(), current)


def restore_verified_backup(source: Path, *, vault_file: Path, settings_file: Path | None,
                            backup_password: str, vault_password: str | SecretText,
                            replace: bool = False, allow_rollback: bool = False,
                            factors: FactorSecrets | None = None,
                            recovery_phrase: str | None = None,
                            drop_current_shares: bool = False) -> dict[str, Any]:
    """Restore into a new profile by default; caller must explicitly request replacement.

    Replacing keeps the replaced vault's shared collections (``keep_current_shares``); a replaced vault that does
    not open with ``vault_password`` is refused unless ``drop_current_shares`` accepts losing them.

    Restoring a copy that is older than the rollback anchor beside ``vault_file``
    raises ``RollbackRequiresConfirmation`` before anything is written unless
    ``allow_rollback`` is set.

    A v4 vault needs its ``factors`` (``FactorRequired`` before any Argon2
    otherwise).  With ``recovery_phrase`` the copy is opened with the phrase
    instead and ``vault_password`` becomes its new master password, which
    drops the factors; the result's ``factors_removed`` lists them.
    """
    payload = _read_backup_payload(source, backup_password)
    secret, owned = _vault_secret(vault_password, _VERIFY_FAILED)
    try:
        return _restore_verified(payload, secret, vault_file=vault_file, settings_file=settings_file,
                                 replace=replace, allow_rollback=allow_rollback, factors=factors,
                                 recovery_phrase=recovery_phrase, drop_current_shares=drop_current_shares)
    finally:
        if owned:
            secret.wipe()


def _restore_verified(payload: dict[str, Any], vault_password: SecretText, *, vault_file: Path,
                      settings_file: Path | None, replace: bool, allow_rollback: bool,
                      factors: FactorSecrets | None = None, recovery_phrase: str | None = None,
                      drop_current_shares: bool = False) -> dict[str, Any]:
    from .settings import AppSettings
    info = _verify_payload(payload, vault_password, factors=factors, recovery_phrase=recovery_phrase)
    if vault_file.exists() and not replace:
        raise BackupError("Destination already has a vault. Restore as a new profile instead.")
    with private_temporary_directory("lgk-restore-check-") as directory:
        probe_path = Path(directory) / "vault.json"
        atomic_write_json(probe_path, payload["vault"])
        probe = _open_backup_vault(probe_path, vault_password, factors=factors, recovery_phrase=recovery_phrase,
                                   upgrade_envelope=False)
        try:
            _check_restore_rollback(probe, vault_file, allow_rollback=allow_rollback)
        finally:
            probe.lock()
    # Shared collections are never restored from a backup: the replaced vault's shares are kept (refused before
    # anything is written when it does not open).
    current = _current_catalog(vault_file if replace else None, vault_password, factors=factors,
                               drop_current_shares=drop_current_shares)
    if replace and vault_file.exists():
        # Preserve the old encrypted file before replacement, never a plaintext copy.
        previous = vault_file.parent / "Backups" / (f"before-restore-{time.time_ns()}.json")
        atomic_write_json(previous, read_json(vault_file))
    # Restored credentials must not silently retain per-entry automatic sign-in approvals.
    # Re-encrypt the sanitized payload in an encrypted-only temporary file.
    with private_temporary_directory("lgk-restore-") as directory:
        # Profile-specific settings are restored through their normal validation.
        # Autostart/external requests/automatic sign-in are OFF for a restored profile.
        # They are staged here and written only after the vault, so a failed vault write never leaves the
        # destination with new settings beside an old or missing vault (scan core 3, L4).
        restored_settings: Any = None
        if settings_file is not None:
            raw = payload.get("settings")
            if isinstance(raw, dict):
                _sanitize_restored_settings(raw)
                _keep_device_settings(raw, _current_device_settings(settings_file))
                staged_settings = Path(directory) / "settings.json"
                atomic_write_json(staged_settings, raw)
                AppSettings.load(staged_settings).save(staged_settings)
                restored_settings = read_json(staged_settings)
        temporary = Path(directory) / "vault.json"
        atomic_write_json(temporary, payload["vault"])
        session = _open_backup_vault(temporary, vault_password, factors=factors, recovery_phrase=recovery_phrase)
        try:
            _sanitize_restored_session(session)
            _keep_current_shares_in(session, current)
            if recovery_phrase is not None:
                removed = _finish_phrase_restore(session, vault_password)
                if removed:
                    info = {**info, "factors_removed": removed}
            atomic_write_json(vault_file, read_json(temporary))
            # Mint the anchor with the restored vault's own data key; a confirmed
            # rollback replaces the newer anchor instead of resetting it to zero.
            session.write_rollback_anchor(vault_file)
            _forget_removal_watch(vault_file)
        finally:
            session.lock()
    if restored_settings is not None and settings_file is not None:
        atomic_write_json(settings_file, restored_settings)
    return info


# Full profile backups are deliberately a separate format.  The v1 limit above
# is part of the compatibility contract and must not be raised for old .lgk
# envelopes.
FULL_BACKUP_VERSION = 2
FULL_BACKUP_FORMAT = "localgatekeys-full-backup"
FULL_BACKUP_AAD = b"localgatekeys|encrypted-full-profile-backup|v2"
FULL_BACKUP_KDF = dict(BACKUP_KDF)
MAX_FULL_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_FULL_BACKUP_ENTRIES = 20_005  # catalog attachment bound plus vault/settings metadata
MAX_FULL_BACKUP_MEMBER_BYTES = 32 * 1024 * 1024
MAX_FULL_BACKUP_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_FULL_BACKUP_HEADER_BYTES = 64 * 1024
MAX_FULL_BACKUP_SETTINGS_BYTES = 1 * 1024 * 1024

# Names used by callers that adopted the M3 terminology before the final
# constants were chosen.  Keeping these aliases costs nothing and makes the
# size/entry bounds straightforward to discover.
MAX_BACKUP_V2_BYTES = MAX_FULL_BACKUP_BYTES
MAX_FULL_ARCHIVE_BYTES = MAX_FULL_BACKUP_BYTES
MAX_BACKUP_V2_ENTRIES = MAX_FULL_BACKUP_ENTRIES


class BackupCancelled(BackupError):
    """A full backup operation was cancelled before publication."""


def _full_cancelled(cancel: Callable[[], bool] | Any | None) -> None:
    if cancel is None:
        return
    try:
        value = cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())
    except Exception as exc:  # noqa: BLE001
        raise BackupCancelled("Backup operation was cancelled") from exc
    if value:
        raise BackupCancelled("Backup operation was cancelled")


def _full_progress(
    callback: Callable[..., Any] | None,
    phase: str,
    completed: int,
    total: int,
) -> None:
    """Call progress hooks with metadata only; never pass names or data."""
    if callback is None:
        return
    event = {"phase": phase, "completed": int(completed), "total": int(total)}
    try:
        callback(phase, int(completed), int(total))
    except TypeError:
        try:
            callback(event)
        except TypeError:
            callback(int(completed), int(total))


def _full_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BackupError(f"{label} must be a regular non-symlink file")


def _full_bounded_read(
    path: Path,
    limit: int,
    *,
    label: str,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    phase: str = "read",
) -> bytes:
    path = Path(path)
    _full_regular_file(path, label)
    try:
        size = path.stat().st_size
        if size > limit:
            raise BackupError(f"{label} is too large")
        chunks: list[bytes] = []
        total = 0
        with path.open("rb") as handle:
            while True:
                _full_cancelled(cancel)
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise BackupError(f"{label} is too large")
                _full_progress(progress, phase, total, max(size, total))
        if path.stat().st_size != size:
            raise BackupError(f"{label} changed while it was being read")
        return b"".join(chunks)
    except BackupError:
        raise
    except OSError as exc:
        raise BackupError(f"Could not read {label}") from exc


def _full_atomic_bytes(path: Path, data: bytes) -> None:
    """Write bounded binary data atomically, with no destination plaintext temp."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".lgk-full-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _full_temp_dir(parent: Path, prefix: str) -> Path:
    """Create a random working directory usable by the current Windows user."""
    parent = Path(parent)
    try:
        parent.mkdir(parents=True, exist_ok=True)
        for _ in range(16):
            candidate = parent / f"{prefix}{uuid.uuid4().hex}"
            try:
                candidate.mkdir()
                return candidate
            except FileExistsError:
                continue
    except OSError as exc:
        raise BackupError("Could not create full backup staging directory") from exc
    raise BackupError("Could not create a unique full backup staging directory")


def _full_canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _full_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _full_validate_settings(value: Any) -> dict[str, Any]:
    """Normalize settings through the same bounds used by AppSettings.save."""
    from .hotkey import normalize_hotkey
    from .settings import (
        LOADABLE_SETTINGS_VERSIONS,
        SETTINGS_VERSION,
        AppSettings,
        _bounded,
        _validated_backup_count,
        _validated_clipboard_timeout,
        _validated_timeout,
    )

    if not isinstance(value, dict):
        raise BackupError("Backup settings must be an object")
    version = value.get("version", 1)
    if version not in LOADABLE_SETTINGS_VERSIONS:
        raise BackupError("Unsupported backup settings version")
    defaults = AppSettings()
    args: dict[str, Any] = {}
    for field in dataclasses.fields(defaults):
        name = field.name
        default = getattr(defaults, name)
        raw = value.get(name, default)
        if isinstance(default, bool):
            args[name] = raw if type(raw) is bool else default
    # The same migrations as AppSettings.load: neither stored "on" was ever chosen.
    if version < 7:
        args["website_icons"] = defaults.website_icons
    if version < 8:
        args["legacy_gesture_compat"] = defaults.legacy_gesture_compat
    args.update(
        auto_lock_seconds=_validated_timeout(value.get("auto_lock_seconds", defaults.auto_lock_seconds)),
        max_session_seconds=_validated_timeout(value.get("max_session_seconds", defaults.max_session_seconds),
                                                default=defaults.max_session_seconds),
        idle_source=value.get("idle_source") if value.get("idle_source") in ("computer", "vault") else defaults.idle_source,
        clipboard_clear_seconds=_validated_clipboard_timeout(
            value.get("clipboard_clear_seconds", defaults.clipboard_clear_seconds)
        ),
        automatic_backup_count=_validated_backup_count(
            value.get("automatic_backup_count", defaults.automatic_backup_count)
        ),
        trash_retention_days=_bounded(value.get("trash_retention_days", defaults.trash_retention_days), 1, 365, 30),
    )
    try:
        args["quick_access_hotkey"] = normalize_hotkey(
            value.get("quick_access_hotkey", defaults.quick_access_hotkey)
        )
    except ValueError:
        args["quick_access_hotkey"] = defaults.quick_access_hotkey
    result = {"version": SETTINGS_VERSION, **dataclasses.asdict(AppSettings(**args))}
    # Per-device choices (UI language, key-file paths and "Always ask", the developer pack's SSH agent and CLI
    # switches, allow-lists and saved setup values): never exported, never restored.
    for name in DEVICE_ONLY_SETTINGS:
        result.pop(name, None)
    return result


DEVICE_ONLY_SETTINGS = ("language", "developer_ssh_agent", "developer_ssh_keys", "developer_saved_env",
                        "developer_saved_git", "developer_cli", "developer_cli_items", "developer_last_scan",
                        "unlock_keyfile_paths", "unlock_factors_always_ask", "agent_items",
                        "agent_exposure_dismissed")
# Per-device choices a restore turns off instead of keeping: restored items arrive with "AI agents may use this
# item" off (agent_gate), even when this device had allowed items with the same ids.
RESET_ON_RESTORE = {"agent_items": [], "agent_exposure_dismissed": []}


def _current_device_settings(settings_file: Path | None) -> dict[str, Any]:
    """This device's stored per-device settings (``DEVICE_ONLY_SETTINGS``); empty without a settings file."""
    if settings_file is None or not Path(settings_file).exists():
        return {}
    try:
        raw = read_json(Path(settings_file))
    except (OSError, ValueError, TypeError, RecursionError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {name: raw[name] for name in DEVICE_ONLY_SETTINGS if name in raw}


def _keep_device_settings(settings: dict[str, Any], current: dict[str, Any]) -> None:
    for name in DEVICE_ONLY_SETTINGS:
        settings.pop(name, None)
    settings.update(current)
    # Absent means the default (off), so only a value this device kept needs resetting.
    settings.update({name: list(value) for name, value in RESET_ON_RESTORE.items() if name in settings})


def _full_read_settings(path: Path | None) -> dict[str, Any]:
    if path is None or not Path(path).exists():
        return _full_validate_settings({})
    try:
        raw = read_json(Path(path))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise BackupError("Could not read profile settings") from exc
    return _full_validate_settings(raw)


def _full_validate_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise BackupError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BackupError(f"{label} must be a JSON object")
    return value


def _full_filtered_vault(data: bytes, vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None) -> bytes:
    """The vault member's bytes: checked, then (with ``vault_filter``) what the filter makes of the file."""
    vault = _full_validate_json_object(data, "Vault")
    if vault_filter is None:
        return data
    filtered = _full_canonical(vault_filter(vault))
    if len(filtered) > MAX_FULL_BACKUP_MEMBER_BYTES:
        raise BackupError("Vault is too large")
    return filtered


def _full_validate_generation(data: bytes) -> None:
    value = _full_validate_json_object(data, "Vault generation metadata")
    generation = value.get("generation")
    if value.get("version") != 1 or type(generation) is not int or not 0 <= generation <= 2**63 - 1:
        raise BackupError("Vault generation metadata is malformed")


def _full_validate_sidecar_header(data: bytes, *, expected_id: str | None = None) -> dict[str, Any]:
    """Validate the unauthenticated sidecar framing before any publication."""
    from .attachments import ATTACHMENT_MAGIC, MAX_ATTACHMENT_SIZE, SUPPORTED_ATTACHMENT_VERSIONS

    if len(data) > MAX_ATTACHMENT_SIZE + 64 * 1024:
        raise BackupError("Attachment sidecar is too large")
    if not data.startswith(ATTACHMENT_MAGIC) or len(data) < len(ATTACHMENT_MAGIC) + 4:
        raise BackupError("Attachment sidecar has an invalid header")
    offset = len(ATTACHMENT_MAGIC)
    header_length = int.from_bytes(data[offset:offset + 4], "big")
    if not 1 <= header_length <= 8 * 1024:
        raise BackupError("Attachment sidecar header is malformed")
    start = offset + 4
    end = start + header_length
    if end + 12 > len(data):
        raise BackupError("Attachment sidecar is truncated")
    header = _full_validate_json_object(data[start:end], "Attachment sidecar header")
    if (header.get("format") != "localgatekeys-attachment"
            or header.get("version") not in SUPPORTED_ATTACHMENT_VERSIONS):
        raise BackupError("Unsupported attachment sidecar format")
    attachment_id = str(header.get("id", ""))
    try:
        parsed_id = str(uuid.UUID(attachment_id))
    except (ValueError, TypeError, AttributeError):
        raise BackupError("Attachment sidecar ID is malformed") from None
    if expected_id is not None and parsed_id != expected_id:
        raise BackupError("Attachment sidecar ID does not match its manifest")
    ciphertext_length = len(data) - (end + 12)
    if ciphertext_length < 16 or ciphertext_length - 16 > MAX_ATTACHMENT_SIZE:
        raise BackupError("Attachment sidecar length is out of bounds")
    if header.get("version") == 1:
        size = header.get("size")
        digest = header.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_ATTACHMENT_SIZE:
            raise BackupError("Attachment sidecar size is malformed")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)):
            raise BackupError("Attachment sidecar digest is malformed")
        if ciphertext_length != size + 16:
            raise BackupError("Attachment sidecar length does not match its header")
        digest = digest.lower()
    else:
        # v2 headers carry identity only; the plaintext size follows from the
        # AES-GCM body and the digest is verified from the encrypted catalog.
        if set(header) != {"format", "version", "id", "store_id"}:
            raise BackupError("Attachment sidecar header is malformed")
        size = ciphertext_length - 16
        digest = None
    return {"id": parsed_id, "store_id": header.get("store_id"), "size": size,
            "sha256": digest, "header": header}


def _full_resolve_paths(
    *,
    profile_dir: Path | None,
    vault_file: Path | None,
    settings_file: Path | None,
    attachment_store_dir: Path | None,
    attachment_store: Path | None,
) -> tuple[Path, Path, Path | None, Path, Path]:
    if attachment_store_dir is not None and attachment_store is not None:
        if Path(attachment_store_dir) != Path(attachment_store):
            raise BackupError("Attachment store paths disagree")
    attachment_store_dir = attachment_store_dir or attachment_store
    if profile_dir is not None:
        root = Path(profile_dir)
        expected_vault = root / "vault.json"
        expected_settings = root / "settings.json"
        expected_attachments = root / "Attachments"
        if vault_file is not None and Path(vault_file) != expected_vault:
            raise BackupError("Explicit vault path does not belong to profile_dir")
        if settings_file is not None and Path(settings_file) != expected_settings:
            raise BackupError("Explicit settings path does not belong to profile_dir")
        if attachment_store_dir is not None and Path(attachment_store_dir) != expected_attachments:
            raise BackupError("Explicit attachment path does not belong to profile_dir")
        vault_file = expected_vault
        settings_file = expected_settings
        attachment_store_dir = expected_attachments
    elif vault_file is None:
        raise BackupError("A profile_dir or vault_file is required")
    else:
        vault_file = Path(vault_file)
        if attachment_store_dir is None:
            attachment_store_dir = vault_file.parent / "Attachments"
    vault_file = Path(vault_file)
    root = Path(profile_dir) if profile_dir is not None else vault_file.parent
    anchor = vault_file.with_name(vault_file.stem + ".generation.json")
    return root, vault_file, Path(settings_file) if settings_file is not None else None, Path(attachment_store_dir), anchor


def _full_source_sidecars(
    attachment_store_dir: Path,
    *,
    cancel: Callable[[], bool] | Any | None,
    progress: Callable[..., Any] | None,
) -> list[dict[str, Any]]:
    if not attachment_store_dir.exists():
        return []
    if attachment_store_dir.is_symlink() or not attachment_store_dir.is_dir():
        raise BackupError("Attachment store must be a regular directory")
    result: list[dict[str, Any]] = []
    try:
        paths = sorted(attachment_store_dir.glob("*.blob"), key=lambda item: item.name)
    except OSError as exc:
        raise BackupError("Could not enumerate attachment store") from exc
    for index, path in enumerate(paths, start=1):
        _full_cancelled(cancel)
        if path.is_symlink() or not path.is_file():
            continue
        try:
            attachment_id = str(uuid.UUID(path.stem))
        except (ValueError, TypeError, AttributeError):
            # Temporary/unrelated files are not part of the attachment store.
            continue
        data = _full_bounded_read(
            path,
            MAX_FULL_BACKUP_MEMBER_BYTES,
            label="Attachment sidecar",
            cancel=cancel,
            progress=progress,
            phase="scan-attachments",
        )
        parsed = _full_validate_sidecar_header(data, expected_id=attachment_id)
        result.append({
            "kind": "attachment",
            "target": f"{attachment_id}.blob",
            "attachment_id": attachment_id,
            "source": path,
            "size": len(data),
            "sha256": _full_sha256(data),
            "sidecar_size": parsed["size"],
        })
        _full_progress(progress, "scan-attachments", index, max(index, len(paths)))
        if len(result) + 3 > MAX_FULL_BACKUP_ENTRIES:
            raise BackupError("Full backup contains too many entries")
    return result


def _full_entry_bytes(entry: dict[str, Any], *, cancel: Callable[[], bool] | Any | None,
                      progress: Callable[..., Any] | None) -> bytes:
    _full_cancelled(cancel)
    if "data" in entry:
        data = entry["data"]
    else:
        data = _full_bounded_read(
            Path(entry["source"]),
            MAX_FULL_BACKUP_MEMBER_BYTES,
            label="Attachment sidecar",
            cancel=cancel,
            progress=progress,
            phase="read-attachment",
        )
    if len(data) != entry["size"] or _full_sha256(data) != entry["sha256"]:
        raise BackupError("A source changed while the full backup was being written")
    return data


def _full_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0o600 << 16
    return info


def _full_encrypt(data: bytes, *, key: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def export_full_backup(
    destination: Path,
    *,
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    attachment_store: Path | None = None,
    profile_name: str | None = None,
    backup_password: str,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    kdf_overrides: dict[str, int] | None = None,
    vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Export a complete profile into an authenticated, encrypted v2 container.

    ZIP member names are fixed safe tokens.  The manifest, vault JSON, settings
    and opaque encrypted sidecars are all authenticated with the backup key;
    only the version/KDF header is visible without the password.
    ``vault_filter``: what the vault file becomes in the backup (``without_share_records``).
    """
    root, vault_file, settings_file, attachment_dir, anchor = _full_resolve_paths(
        profile_dir=profile_dir,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_store_dir,
        attachment_store=attachment_store,
    )
    _full_cancelled(cancel)
    vault_data = _full_bounded_read(vault_file, MAX_FULL_BACKUP_MEMBER_BYTES, label="Vault", cancel=cancel,
                                    progress=progress, phase="read-vault")
    vault_data = _full_filtered_vault(vault_data, vault_filter)
    settings = _full_read_settings(settings_file)
    settings_data = _full_canonical(settings)
    if len(settings_data) > MAX_FULL_BACKUP_SETTINGS_BYTES:
        raise BackupError("Profile settings are too large")
    entries: list[dict[str, Any]] = [
        {"kind": "vault", "target": "vault.json", "data": vault_data,
         "size": len(vault_data), "sha256": _full_sha256(vault_data)},
        {"kind": "settings", "target": "settings.json", "data": settings_data,
         "size": len(settings_data), "sha256": _full_sha256(settings_data)},
    ]
    if anchor.exists():
        anchor_data = _full_bounded_read(anchor, 64 * 1024, label="Vault generation metadata", cancel=cancel,
                                         progress=progress, phase="read-vault")
        _full_validate_generation(anchor_data)
        entries.append({"kind": "generation", "target": "generation.json", "data": anchor_data,
                        "size": len(anchor_data), "sha256": _full_sha256(anchor_data)})
    entries.extend(_full_source_sidecars(attachment_dir, cancel=cancel, progress=progress))
    if len(entries) > MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup contains too many entries")
    if profile_name is None:
        profile_name = root.name or "Restored profile"
    if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 256 or "\x00" in profile_name:
        raise BackupError("Profile name is malformed")

    salt = os.urandom(16)
    kdf = _new_kdf(kdf_overrides)
    key = _derive(backup_password, salt, kdf)
    header = {
        "format": FULL_BACKUP_FORMAT,
        "version": FULL_BACKUP_VERSION,
        "kdf": {**kdf, "salt": _b64e(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce_bytes": 12, "tag_bytes": 16},
        "entry_count": len(entries),
    }
    header_data = _full_canonical(header)
    if len(header_data) > MAX_FULL_BACKUP_HEADER_BYTES:
        raise BackupError("Full backup header is too large")
    manifest_entries: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        member = f"data/{index:08d}.bin"
        entry["member"] = member
        record = {key: entry[key] for key in ("kind", "target", "size", "sha256")}
        if entry["kind"] == "attachment":
            record["attachment_id"] = entry["attachment_id"]
            record["sidecar_size"] = entry["sidecar_size"]
        record["member"] = member
        manifest_entries.append(record)
    manifest = {
        "version": FULL_BACKUP_VERSION,
        "profile_name": profile_name,
        "entries": manifest_entries,
        "created_at": int(time.time()),
    }
    manifest_data = _full_canonical(manifest)
    if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
        raise BackupError("Full backup manifest is too large")
    manifest_digest = hashlib.sha256(manifest_data).digest()
    manifest_blob = _full_encrypt(manifest_data, key=key, aad=FULL_BACKUP_AAD + header_data)

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_dir():
        raise BackupError("Backup destination must be a file")
    fd, name = tempfile.mkstemp(prefix=".lgk-full-backup-", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w+b") as handle:
            with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.writestr(_full_zip_info("header.json"), header_data)
                archive.writestr(_full_zip_info("manifest.bin"), manifest_blob)
                total = len(entries)
                for index, entry in enumerate(entries, start=1):
                    _full_cancelled(cancel)
                    data = _full_entry_bytes(entry, cancel=cancel, progress=progress)
                    aad = FULL_BACKUP_AAD + header_data + manifest_digest + entry["member"].encode("ascii")
                    blob = _full_encrypt(data, key=key, aad=aad)
                    archive.writestr(_full_zip_info(entry["member"]), blob)
                    _full_progress(progress, "export", index, total)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.stat().st_size > MAX_FULL_BACKUP_BYTES:
            raise BackupError("Full backup is too large")
        _full_cancelled(cancel)
        os.replace(temporary, destination)
    except BackupError:
        temporary.unlink(missing_ok=True)
        raise
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        raise BackupError("Could not write full backup") from exc
    return {
        "version": FULL_BACKUP_VERSION,
        "profile_name": profile_name,
        "entries": len(entries),
        "attachments": sum(entry["kind"] == "attachment" for entry in entries),
        "bytes": destination.stat().st_size,
    }


def _full_zip_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int,
                   *, cancel: Callable[[], bool] | Any | None = None) -> bytes:
    if info.file_size > limit:
        raise BackupError("Full backup member is too large")
    chunks: list[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as handle:
            while True:
                _full_cancelled(cancel)
                chunk = handle.read(min(1024 * 1024, limit - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise BackupError("Full backup member is too large")
    except BackupError:
        raise
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BackupError("Full backup is truncated or unreadable") from exc
    if total != info.file_size:
        raise BackupError("Full backup member length is inconsistent")
    return b"".join(chunks)


def _full_manifest_entries(manifest: dict[str, Any], header: dict[str, Any],
                           *, expected_version: int = FULL_BACKUP_VERSION) -> list[dict[str, Any]]:
    entries = manifest.get("entries")
    if manifest.get("version") != expected_version or not isinstance(entries, list):
        raise BackupError("Full backup manifest is malformed")
    if len(entries) != header.get("entry_count") or not 2 <= len(entries) <= MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup entry count is invalid")
    profile_name = manifest.get("profile_name")
    if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 256 or "\x00" in profile_name:
        raise BackupError("Full backup profile name is malformed")
    result: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    seen_targets: set[str] = set()
    kinds: set[str] = set()
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise BackupError("Full backup manifest entry is malformed")
        allowed = {"kind", "target", "size", "sha256", "member", "attachment_id", "sidecar_size"}
        if set(raw) - allowed:
            raise BackupError("Full backup manifest contains unsupported fields")
        kind, target, member = raw.get("kind"), raw.get("target"), raw.get("member")
        if kind not in {"vault", "settings", "generation", "attachment"} or not isinstance(target, str):
            raise BackupError("Full backup manifest entry type is invalid")
        expected_member = f"data/{index:08d}.bin"
        if member != expected_member or member in seen_members:
            raise BackupError("Full backup data member name is invalid")
        if kind == "vault" and target != "vault.json":
            raise BackupError("Full backup vault target is invalid")
        if kind == "settings" and target != "settings.json":
            raise BackupError("Full backup settings target is invalid")
        if kind == "generation" and target != "generation.json":
            raise BackupError("Full backup generation target is invalid")
        if kind == "attachment":
            attachment_id = raw.get("attachment_id")
            try:
                attachment_id = str(uuid.UUID(str(attachment_id)))
            except (ValueError, TypeError, AttributeError):
                raise BackupError("Full backup attachment ID is invalid") from None
            if target != f"{attachment_id}.blob" or raw.get("sidecar_size") is None:
                raise BackupError("Full backup attachment target is invalid")
            raw = {**raw, "attachment_id": attachment_id}
        if target in seen_targets:
            raise BackupError("Full backup contains duplicate targets")
        size = raw.get("size")
        digest = raw.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_FULL_BACKUP_MEMBER_BYTES:
            raise BackupError("Full backup member size is invalid")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)):
            raise BackupError("Full backup member digest is invalid")
        if kind == "attachment" and (type(raw.get("sidecar_size")) is not int or raw["sidecar_size"] < 0):
            raise BackupError("Full backup sidecar size is invalid")
        seen_members.add(member)
        seen_targets.add(target)
        kinds.add(kind)
        result.append({**raw, "sha256": digest.lower()})
    if kinds & {"vault"} == set() or "settings" not in kinds:
        raise BackupError("Full backup is missing vault or settings")
    if sum(raw["kind"] == "vault" for raw in result) != 1 or sum(raw["kind"] == "settings" for raw in result) != 1:
        raise BackupError("Full backup contains duplicate vault or settings entries")
    if sum(raw["kind"] == "generation" for raw in result) > 1:
        raise BackupError("Full backup contains duplicate generation metadata")
    return result


def _full_read_container(
    source: Path,
    backup_password: str,
    *,
    on_entry: Callable[[dict[str, Any], bytes], None],
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    _data_key: bytes | bytearray | None = None,
) -> dict[str, Any]:
    """Read and authenticate a full backup.  Version 2 (password) is read below; version 3 (to a backup public key)
    branches to ``_full_read_v3`` right after the header parses.  ``_data_key`` is internal (the v3 writer's
    self-verify, design 9.1) and is refused for v2."""
    source = Path(source)
    _full_regular_file(source, "Full backup")
    try:
        if source.stat().st_size > MAX_FULL_BACKUP_BYTES:
            raise BackupError("Full backup is too large")
        with zipfile.ZipFile(source, "r") as archive:
            infos = archive.infolist()
            if len(infos) < 4 or len(infos) > MAX_FULL_BACKUP_ENTRIES + 2:
                raise BackupError("Full backup has too many archive members")
            info_by_name: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                name = info.filename
                if name in info_by_name or name not in {"header.json", "manifest.bin"} and not (
                    isinstance(name, str) and name.startswith("data/") and name.endswith(".bin")
                ):
                    raise BackupError("Full backup contains an unsafe archive member")
                if not isinstance(name, str) or "\x00" in name or name.startswith(("/", "\\")) or ".." in name.split("/"):
                    raise BackupError("Full backup contains an unsafe archive member")
                if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                    raise BackupError("Full backup compression or ZIP encryption is unsupported")
                if info.file_size > MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024:
                    raise BackupError("Full backup member is too large")
                info_by_name[name] = info
            if set(info_by_name) - {"header.json", "manifest.bin"} and any(
                not name.startswith("data/") for name in info_by_name if name not in {"header.json", "manifest.bin"}
            ):
                raise BackupError("Full backup contains an unsafe archive member")
            header_data = _full_zip_read(archive, info_by_name.get("header.json") or (_ for _ in ()).throw(BackupError("Missing full backup header")),
                                         MAX_FULL_BACKUP_HEADER_BYTES, cancel=cancel)
            header = _full_validate_json_object(header_data, "Full backup header")
            if (header.get("format") == FULL_BACKUP_FORMAT and type(header.get("version")) is int
                    and header.get("version") == FULL_BACKUP_V3_VERSION):
                return _full_read_v3(archive, info_by_name, header_data, header, backup_password,
                                     data_key=_data_key, on_entry=on_entry, cancel=cancel, progress=progress)
            if _data_key is not None:
                raise BackupError("Unsupported full backup format")
            if header.get("format") != FULL_BACKUP_FORMAT or header.get("version") != FULL_BACKUP_VERSION:
                raise BackupError("Unsupported full backup format")
            kdf = header.get("kdf")
            cipher = header.get("cipher")
            if (not isinstance(kdf, dict) or not isinstance(cipher, dict)
                    or cipher.get("name") != "aes-256-gcm" or cipher.get("nonce_bytes") != 12
                    or cipher.get("tag_bytes") != 16):
                raise BackupError("Unsupported full backup encryption parameters")
            _kdf_parameters(kdf)
            salt = _b64d(kdf.get("salt", ""))
            if len(salt) != 16:
                raise BackupError("Malformed full backup KDF salt")
            entry_count = header.get("entry_count")
            if type(entry_count) is not int or not 2 <= entry_count <= MAX_FULL_BACKUP_ENTRIES:
                raise BackupError("Full backup entry count is invalid")
            manifest_info = info_by_name.get("manifest.bin")
            if manifest_info is None:
                raise BackupError("Missing full backup manifest")
            manifest_blob = _full_zip_read(archive, manifest_info, MAX_FULL_BACKUP_MANIFEST_BYTES + 64, cancel=cancel)
            if len(manifest_blob) < 12 + 16:
                raise BackupError("Full backup manifest is truncated")
            key = _derive(backup_password, salt, kdf)
            try:
                manifest_data = AESGCM(key).decrypt(
                    manifest_blob[:12], manifest_blob[12:], FULL_BACKUP_AAD + header_data
                )
            except InvalidTag:
                raise BackupError("Wrong backup password or modified full backup") from None
            if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
                raise BackupError("Full backup manifest is too large")
            manifest = _full_validate_json_object(manifest_data, "Full backup manifest")
            entries = _full_manifest_entries(manifest, header)
            expected_names = {"header.json", "manifest.bin"} | {entry["member"] for entry in entries}
            if set(info_by_name) != expected_names:
                raise BackupError("Full backup members do not match its manifest")
            manifest_digest = hashlib.sha256(manifest_data).digest()
            for index, entry in enumerate(entries, start=1):
                _full_cancelled(cancel)
                info = info_by_name[entry["member"]]
                if info.file_size != entry["size"] + 12 + 16:
                    raise BackupError("Full backup member size does not match its manifest")
                blob = _full_zip_read(archive, info, MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024, cancel=cancel)
                aad = FULL_BACKUP_AAD + header_data + manifest_digest + entry["member"].encode("ascii")
                try:
                    data = AESGCM(key).decrypt(blob[:12], blob[12:], aad)
                except InvalidTag:
                    raise BackupError("Wrong backup password or modified full backup") from None
                if len(data) != entry["size"] or _full_sha256(data) != entry["sha256"]:
                    raise BackupError("Full backup member authentication failed")
                on_entry(entry, data)
                _full_progress(progress, "import", index, len(entries))
            return {"manifest": manifest, "header": header, "entries": entries}
    except BackupError:
        raise
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile, RecursionError) as exc:
        raise BackupError("Could not read full backup") from exc


def _full_validate_staged_vault(
    vault_path: Path,
    attachment_dir: Path,
    *,
    vault_password: SecretText | None,
    attachment_quota_bytes: int,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    factors: FactorSecrets | None = None,
    recovery_phrase: str | None = None,
) -> dict[str, Any]:
    from .vault import VaultError, _read_vault_header

    try:
        _read_vault_header(vault_path)
    except (VaultError, OSError, ValueError, TypeError) as exc:
        raise BackupError("Full backup contains an invalid encrypted vault") from exc
    if not 1 <= int(attachment_quota_bytes) <= 1024 * 1024 * 1024:
        raise BackupError("Attachment quota is outside the accepted bound")
    if vault_password is None:
        return {"verified": False, "entries": None, "attachments": None}
    try:
        session = _open_backup_vault(vault_path, vault_password, factors=factors, recovery_phrase=recovery_phrase)
    except VAULT_PROMPT_ERRORS:
        raise
    except Exception as exc:  # noqa: BLE001 - do not leak vault parser details
        raise BackupError("Backup vault could not be unlocked with the supplied master password") from exc
    try:
        from .attachments import AttachmentStore
        store = AttachmentStore(session, quota_bytes=int(attachment_quota_bytes))
        store.root = Path(attachment_dir)
        records = list(session._payload.get("attachments", []))
        for index, record in enumerate(records, start=1):
            _full_cancelled(cancel)
            store.read_bytes(record["id"], cancel=cancel)
            _full_progress(progress, "validate-attachments", index, len(records))
        if store.usage_bytes() > int(attachment_quota_bytes):
            raise BackupError("Restored attachments exceed the attachment quota")
        return {
            "verified": True,
            "entries": len(session.summaries()),
            "deleted_entries": len(session.trash_summaries()),
            "attachments": len(records),
        }
    except BackupError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize catalog/sidecar failures
        from .attachments import AttachmentError
        # Attachment/vault errors carry fixed, secret-free messages; surface
        # them so a failed check names the actual problem.
        detail = f": {exc}" if isinstance(exc, (AttachmentError, VaultError)) else f" ({type(exc).__name__})"
        raise BackupError(f"Backup catalog or attachment sidecar validation failed{detail}") from exc
    finally:
        session.lock()


def _full_sanitize_staged_vault(staged_vault: Path, vault_password: SecretText, *, destination_vault: Path,
                                allow_rollback: bool, factors: FactorSecrets | None = None,
                                recovery_phrase: str | None = None,
                                drop_current_shares: bool = False) -> tuple[list[str], Any]:
    """Apply the restore rollback check and sanitising to the staged copy before publication.

    With ``recovery_phrase`` the copy opens with the phrase and ``vault_password`` becomes its new master
    password; the dropped factor kinds are returned (``[]`` otherwise).  The staged copy's session is returned
    still open: once the copy is published, it sets the destination's rollback marks (``mark_restored``); the
    caller locks it.  Until then nothing outside the folder names the destination.
    """
    try:
        session = _open_backup_vault(staged_vault, vault_password, factors=factors, recovery_phrase=recovery_phrase)
    except VAULT_PROMPT_ERRORS:
        raise
    except Exception as exc:  # noqa: BLE001 - do not leak vault parser details
        raise BackupError("Backup vault could not be unlocked with the supplied master password") from exc
    try:
        # Raises RollbackRequiresConfirmation before anything is written.
        _check_restore_rollback(session, destination_vault, allow_rollback=allow_rollback)
        # Shared collections are never restored from a backup: the replaced vault's shares are kept.
        current = _current_catalog(destination_vault, vault_password, factors=factors,
                                   drop_current_shares=drop_current_shares)
        with session.transaction():
            _sanitize_restored_session(session)
            session.set_hello_binding(None)
            session.set_face_binding(None)
            session.set_fido_binding(None)
            keep_current_shares(session._require_payload(), current)
        removed = _finish_phrase_restore(session, vault_password) if recovery_phrase is not None else []
        return removed, session
    except BaseException:
        session.lock()
        raise


def _full_profile_nonempty(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_dir():
        return True
    try:
        return any(path.iterdir())
    except OSError:
        return True


def _full_existing(path: Path) -> bool:
    return path.is_symlink() or path.exists()


def _full_make_pre_restore_backup(
    *,
    destination_root: Path,
    vault_file: Path,
    settings_file: Path | None,
    attachment_dir: Path,
    backup_password: str,
) -> Path:
    if not _full_existing(vault_file):
        raise BackupError("Replacement requires an existing vault to back up first")
    backup_dir = destination_root / "Backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    candidate = backup_dir / f"before-restore-{time.time_ns()}-{os.getpid()}.lgk"
    export_full_backup(
        candidate,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_dir,
        profile_name=destination_root.name or "Previous profile",
        backup_password=backup_password,
    )
    return candidate


def _full_publish(
    stage_root: Path,
    *,
    profile_dir: Path | None,
    vault_file: Path,
    settings_file: Path | None,
    attachment_dir: Path,
    anchor: Path,
    replace: bool,
) -> None:
    targets: list[tuple[Path, Path, bool]] = [
        (stage_root / vault_file.name, vault_file, True),
        (stage_root / attachment_dir.name, attachment_dir, True),
    ]
    if settings_file is not None:
        targets.append((stage_root / settings_file.name, settings_file, True))
    stage_anchor = stage_root / anchor.name
    if stage_anchor.exists() or replace:
        targets.append((stage_anchor, anchor, stage_anchor.exists()))
    rollback_parent = vault_file.parent if vault_file.parent.exists() else stage_root.parent
    rollback_dir = _full_temp_dir(rollback_parent, ".lgk-full-rollback-")
    moved_old: list[tuple[Path, Path]] = []
    moved_new: list[Path] = []
    created_parents: list[Path] = []
    keep_rollback = False
    try:
        for index, (_stage, target, _required) in enumerate(targets):
            if _full_existing(target):
                if not replace:
                    raise BackupError("Destination already contains a profile component")
                old = rollback_dir / f"{index}-{target.name}"
                os.replace(target, old)
                moved_old.append((old, target))
        for stage, target, required in targets:
            if not stage.exists():
                if required:
                    raise BackupError("Full backup staging data is incomplete")
                continue
            if not target.parent.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                created_parents.append(target.parent)
            os.replace(stage, target)
            moved_new.append(target)
    except BaseException as exc:
        for target in reversed(moved_new):
            try:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
            except OSError:
                pass
        for old, target in reversed(moved_old):
            try:
                os.replace(old, target)
            except OSError:
                # The previous profile could not be put back: keep the rollback
                # copy (it holds the old vault) and name it in the error.
                keep_rollback = True
        if keep_rollback:
            raise BackupError(f"Could not put the previous profile back; it is kept in {rollback_dir}") from exc
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Could not publish restored profile") from exc
    finally:
        if not keep_rollback:
            shutil.rmtree(rollback_dir, ignore_errors=True)
        for parent in reversed(created_parents):
            try:
                parent.rmdir()
            except OSError:
                pass


def _full_restore_stage_parent(vault_file: Path, *, dry_run: bool, stage_parent: Path | None) -> Path:
    """Where a full restore stages its decrypted inner layer: never beside the backup file.

    A dry run stages in the owner-only private temporary folder.  A real restore stages there too when it is on
    the destination's volume, and otherwise in the destination's nearest existing folder, so the final
    ``os.replace`` stays on one volume.  The destination itself is never created here.
    """
    if stage_parent is not None:
        return Path(stage_parent)
    if dry_run:
        try:
            return private_temp_root()
        except OSError as exc:
            raise BackupError("Could not create the private staging folder") from exc
    existing = Path(vault_file).parent
    while not existing.exists() and existing.parent != existing:
        existing = existing.parent
    try:
        private = private_temp_root()
        if private.stat().st_dev == existing.stat().st_dev:
            return private
    except OSError:
        pass
    return existing


def restore_full_backup(source: Path, **kwargs: Any) -> dict[str, Any]:
    """Preflight and atomically restore a complete v2 profile (see ``_restore_full_backup``).

    ``vault_password`` may be a ``str`` or a ``SecretText``; it is converted once here and the
    same buffer is used for every unlock.  A ``str`` copy is wiped before return, a ``SecretText``
    stays the caller's.
    """
    vault_password = kwargs.pop("vault_password", None)
    if vault_password is None:
        return _restore_full_backup(source, vault_password=None, **kwargs)
    secret, owned = _vault_secret(vault_password,
                                  "Backup vault could not be unlocked with the supplied master password")
    try:
        return _restore_full_backup(source, vault_password=secret, **kwargs)
    finally:
        if owned:
            secret.wipe()


def _restore_full_backup(
    source: Path,
    *,
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    attachment_store: Path | None = None,
    backup_password: str,
    vault_password: SecretText | None = None,
    factors: FactorSecrets | None = None,
    recovery_phrase: str | None = None,
    validate_vault_password: bool = False,
    validate_master_password: bool = False,
    replace: bool = False,
    allow_rollback: bool = False,
    drop_current_shares: bool = False,
    dry_run: bool = False,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    _data_key: bytes | bytearray | None = None,
    _stage_parent: Path | None = None,
    _heir_restore: bool = False,
    _mark_destination: bool = True,
) -> dict[str, Any]:
    """Preflight and atomically restore a complete v2 (or v3) profile.

    ``_data_key`` is internal: the v3 writer's self-verify (design 9.1) runs this as a dry run with the data key
    instead of a password.  It is refused for anything but a dry run.  ``_stage_parent`` (internal, dry runs
    only) names the staging folder; without it a dry run stages in ``private_temp_root()`` and a real restore on
    the destination's volume (``_full_restore_stage_parent``), never beside ``source``, which may be a mirror
    (cloud) folder.

    With the master password, the destination's rollback marks are set to the restored generation once the
    profile is published, never before.  ``_mark_destination=False`` (internal): the destination is itself a
    staging folder the caller renames into place and marks there (``recovery.restore_as_new_profile``,
    ``heir_flow.combine_and_restore``).

    ``vault_password`` is already a ``SecretText`` here; the caller owns it.

    A v4 vault (key file / YubiKey) needs ``factors``; without them every unlock below raises
    ``FactorRequired`` before its Argon2 runs, and nothing is published.  ``recovery_phrase`` opens the
    vault with its phrase instead: ``vault_password`` is then the restored vault's new master password,
    the factors are dropped and ``factors_removed`` in the result lists them.

    The only temporary files are encrypted vault JSON and already encrypted
    attachment sidecars.  Settings stay in memory until the destination commit.

    Like ``restore_verified_backup``, the restored profile has autostart,
    external requests and automatic sign-in switched off, and (when the vault
    master password is supplied) every credential's automatic sign-in and
    desktop-fill approval and the Windows Hello / camera bindings revoked.
    Replacing an existing vault requires the master password, and replacing
    one that is newer than the backup (or belongs to another key lineage)
    raises ``RollbackRequiresConfirmation`` before anything is written unless
    ``allow_rollback`` is set.
    """
    if (validate_vault_password or validate_master_password) and vault_password is None:
        raise BackupError("A vault master password is required for requested validation")
    if recovery_phrase is not None and vault_password is None:
        raise BackupError("A new vault master password is required for a recovery-phrase restore")
    # A data key opens a v3 file without its password: the writer's self-verify (a dry run), or an emergency
    # access restore (``heir_flow`` passes ``_heir_restore=True``), which also needs the vault's recovery phrase
    # to open the profile inside.  Nothing else may restore with a raw data key.
    heir_restore = _heir_restore is True and recovery_phrase is not None
    if (_data_key is not None and not dry_run and not heir_restore) or \
            (_stage_parent is not None and not dry_run):
        raise BackupError("A data key is accepted only for a verification dry run")
    root, vault_file, settings_file, attachment_dir, anchor = _full_resolve_paths(
        profile_dir=profile_dir,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_store_dir,
        attachment_store=attachment_store,
    )
    if profile_dir is not None and _full_existing(root) and not replace and _full_profile_nonempty(root):
        raise BackupError("Destination profile already exists")
    if not replace:
        for target in (vault_file, settings_file, attachment_dir, anchor):
            if target is not None and _full_existing(target):
                raise BackupError("Destination already contains a profile component")
    elif not dry_run and vault_password is None and (_full_existing(vault_file) or _full_existing(anchor)):
        raise BackupError("Replacing an existing vault requires the backup's vault master password")
    # Stage in a separate folder until every authenticated member and the vault have passed validation, so
    # dry-run and failed restores never create destination directories as a side effect.  Never
    # beside the source: it may be a mirror (cloud) folder, and the stage holds the backup's inner layer with the
    # backup-password layer removed (scan core 3, M1).
    stage_root = _full_temp_dir(_full_restore_stage_parent(vault_file, dry_run=dry_run, stage_parent=_stage_parent),
                                ".lgk-full-restore-")
    stage_attachment_dir = stage_root / attachment_dir.name
    stage_attachment_dir.mkdir(parents=True, exist_ok=True)
    settings_holder: dict[str, Any] = {}
    counts = {"attachments": 0, "attachment_bytes": 0}

    def on_entry(entry: dict[str, Any], data: bytes) -> None:
        kind = entry["kind"]
        if kind == "vault":
            _full_atomic_bytes(stage_root / vault_file.name, data)
        elif kind == "settings":
            if len(data) > MAX_FULL_BACKUP_SETTINGS_BYTES:
                raise BackupError("Restored settings are too large")
            settings_holder["value"] = _full_validate_settings(_full_validate_json_object(data, "Restored settings"))
        elif kind == "generation":
            _full_validate_generation(data)
            _full_atomic_bytes(stage_root / anchor.name, data)
        elif kind == "attachment":
            attachment_id = entry["attachment_id"]
            parsed = _full_validate_sidecar_header(data, expected_id=attachment_id)
            if parsed["size"] != entry["sidecar_size"]:
                raise BackupError("Attachment sidecar metadata does not match its manifest")
            if counts["attachment_bytes"] + len(data) > int(attachment_quota_bytes) + 64 * 1024 * max(1, counts["attachments"] + 1):
                raise BackupError("Restored attachments exceed the attachment quota")
            _full_atomic_bytes(stage_attachment_dir / f"{attachment_id}.blob", data)
            counts["attachments"] += 1
            counts["attachment_bytes"] += parsed["size"]
        else:
            raise BackupError("Unsupported full backup entry")

    pre_restore_backup: Path | None = None
    pre_restore_backup_dir = root / "Backups"
    pre_restore_backup_dir_existed = _full_existing(pre_restore_backup_dir)
    published = False
    staged_session: Any = None
    try:
        container_info = _full_read_container(
            source,
            backup_password,
            on_entry=on_entry,
            cancel=cancel,
            progress=progress,
            _data_key=_data_key,
        )
        if not settings_holder or not (stage_root / vault_file.name).exists():
            raise BackupError("Full backup is missing required profile data")
        validation = _full_validate_staged_vault(
            stage_root / vault_file.name,
            stage_attachment_dir,
            vault_password=vault_password,
            attachment_quota_bytes=int(attachment_quota_bytes),
            factors=factors,
            recovery_phrase=recovery_phrase,
        )
        # Quota is measured against the real sidecar ciphertext store as the
        # attachment service does, not only against plaintext record sizes.
        if sum(path.stat().st_size for path in stage_attachment_dir.glob("*.blob")) > int(attachment_quota_bytes):
            raise BackupError("Restored attachments exceed the attachment quota")
        info = {
            "version": container_info["header"]["version"],
            "profile_name": container_info["manifest"]["profile_name"],
            "entries": len(container_info["entries"]),
            "attachments": counts["attachments"],
            "attachment_bytes": counts["attachment_bytes"],
            "verified_vault": bool(validation.get("verified")),
            "dry_run": bool(dry_run),
        }
        if validation.get("entries") is not None:
            info.update({"vault_entries": validation["entries"], "deleted_entries": validation["deleted_entries"]})
        if dry_run:
            return info
        _full_cancelled(cancel)
        _sanitize_restored_settings(settings_holder["value"])
        if vault_password is not None:
            removed, staged_session = _full_sanitize_staged_vault(
                stage_root / vault_file.name, vault_password, destination_vault=vault_file,
                allow_rollback=allow_rollback, factors=factors, recovery_phrase=recovery_phrase,
                drop_current_shares=drop_current_shares)
            if removed:
                info["factors_removed"] = removed
        _full_cancelled(cancel)
        # The destination parent is created by _full_publish only when the
        # final commit starts, and its rollback cleanup removes an empty one
        # if publication fails.
        if replace and (_full_existing(vault_file) or (profile_dir is not None and _full_profile_nonempty(root))):
            pre_restore_backup = _full_make_pre_restore_backup(
                destination_root=root,
                vault_file=vault_file,
                settings_file=settings_file,
                attachment_dir=attachment_dir,
                backup_password=backup_password,
            )
        if settings_file is not None:
            _keep_device_settings(settings_holder["value"], _current_device_settings(settings_file))
            _full_atomic_bytes(stage_root / settings_file.name, _full_canonical(settings_holder["value"]))
        _full_publish(
            stage_root,
            profile_dir=profile_dir,
            vault_file=vault_file,
            settings_file=settings_file,
            attachment_dir=attachment_dir,
            anchor=anchor,
            replace=replace,
        )
        published = True
        if staged_session is not None and _mark_destination:
            # Only now that the restored vault is in place: a restore that stopped earlier (cancelled, or its
            # pre-restore backup or publish failed) left the vault there and its marks as they were.
            staged_session.mark_restored(vault_file)
        _forget_removal_watch(vault_file)
        return info
    except BackupError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise BackupError("Full backup restore failed") from exc
    finally:
        if staged_session is not None:
            staged_session.lock()
        if not published:
            if pre_restore_backup is not None:
                pre_restore_backup.unlink(missing_ok=True)
            if not pre_restore_backup_dir_existed and pre_restore_backup_dir.is_dir():
                try:
                    next(pre_restore_backup_dir.iterdir())
                except StopIteration:
                    pre_restore_backup_dir.rmdir()
                except OSError:
                    pass
        shutil.rmtree(stage_root, ignore_errors=True)


def preflight_full_backup(source: Path, **kwargs: Any) -> dict[str, Any]:
    """Run full-backup restore validation without touching the destination."""
    kwargs["dry_run"] = True
    return restore_full_backup(source, **kwargs)


# Explicit aliases make the v2 API discoverable while retaining the shorter
# names used by early M3 callers.
export_encrypted_full_backup = export_full_backup
restore_encrypted_full_backup = restore_full_backup
verify_full_backup = preflight_full_backup


# --------------------------------------------------------------------------- full backup v3 (to a public key)
# Design: docs/design/backup-public-key-2026-10-31.md sections 3.4, 7.2, 8 and 9.1; vectors tests/vectors/backup/v3.
# Only scheduled backups are written in this format.  The ZIP layout, member names, bounds and manifest are the
# v2 ones; a fresh data key ``dk`` per file is wrapped to the record's X25519 public key.  The manifest and the
# members bind ``core`` (the header without ``recipient``), so a re-lock replaces ``header.json`` only.
# The v1/v2 code above is unchanged (hard rule 1.1): ``_full_read_container`` only gained the ``version == 3``
# branch, and the v3 writer has its own copy of the member collection.
FULL_BACKUP_V3_VERSION = 3
FULL_BACKUP_V3_AAD = b"localgatekeys|encrypted-full-profile-backup|v3"
FULL_BACKUP_CIPHER = {"name": "aes-256-gcm", "nonce_bytes": 12, "tag_bytes": 16}
V3_HEADER_FIELDS = frozenset({"format", "version", "cipher", "entry_count", "recipient"})
V3_RECIPIENT_FIELDS = frozenset({"scheme", "key_id", "key_set_at", "kdf", "ephemeral_public_key", "wrapped_key"})
WRONG_FULL_BACKUP_PASSWORD = "Wrong backup password or modified full backup"  # noqa: S105 - the v2 text (3.4)
MALFORMED_RECIPIENT = "Malformed full backup recipient"
RELOCK_RELOCKED, RELOCK_OLD_FORMAT, RELOCK_OTHER_KEY = "relocked", "old_format", "other_key"


@dataclasses.dataclass(frozen=True)
class _V3Header:
    header: dict[str, Any]
    core: dict[str, Any]
    core_data: bytes
    recipient: dict[str, Any]
    recipient_body: dict[str, Any]
    kdf: dict[str, Any]
    ephemeral_public: bytes
    wrapped: bytes

    def wrap_aad(self) -> bytes:
        from .backup_key import wrap_aad
        return wrap_aad(self.core, self.recipient_body)


def _v3_b64(value: Any, size: int) -> bytes:
    """Canonical padded base64 of exactly ``size`` bytes (as ``backup_key`` reads stored fields)."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 256:
        raise BackupError(MALFORMED_RECIPIENT)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except ValueError:
        raise BackupError(MALFORMED_RECIPIENT) from None
    if _b64e(decoded) != value or len(decoded) != size:
        raise BackupError(MALFORMED_RECIPIENT)
    return decoded


def _v3_parse_header(header_data: bytes, header: Any) -> _V3Header:
    """Section 3.4 strict header check, in reader order, with the v2 messages where v2 has one."""
    from .backup_key import _KEY_ID, KDF_FIELDS, MAX_TIMESTAMP, RECIPIENT_SCHEME
    if (not isinstance(header, dict) or header.get("format") != FULL_BACKUP_FORMAT
            or type(header.get("version")) is not int or header.get("version") != FULL_BACKUP_V3_VERSION
            or set(header) != V3_HEADER_FIELDS):
        raise BackupError("Unsupported full backup format")
    recipient = header["recipient"]
    if not isinstance(recipient, dict) or set(recipient) != V3_RECIPIENT_FIELDS:
        raise BackupError("Unsupported full backup format")
    cipher = header["cipher"]
    if not isinstance(cipher, dict) or _full_canonical(cipher) != _full_canonical(FULL_BACKUP_CIPHER):
        raise BackupError("Unsupported full backup encryption parameters")
    if recipient["scheme"] != RECIPIENT_SCHEME:
        raise BackupError("Unsupported full backup encryption parameters")
    kdf = recipient["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != KDF_FIELDS:
        raise BackupError("Unsupported backup encryption parameters")
    _kdf_parameters(kdf)
    try:
        _v3_b64(kdf["salt"], 16)
    except BackupError:
        raise BackupError("Malformed full backup KDF salt") from None
    entry_count = header["entry_count"]
    if type(entry_count) is not int or not 2 <= entry_count <= MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup entry count is invalid")
    key_id_value, key_set_at = recipient["key_id"], recipient["key_set_at"]
    if not isinstance(key_id_value, str) or not _KEY_ID.fullmatch(key_id_value):
        raise BackupError(MALFORMED_RECIPIENT)
    if type(key_set_at) is not int or not 0 <= key_set_at <= MAX_TIMESTAMP:
        raise BackupError(MALFORMED_RECIPIENT)
    ephemeral_public = _v3_b64(recipient["ephemeral_public_key"], 32)
    wrapped = _v3_b64(recipient["wrapped_key"], 48)
    # The AADs are recomputed from canonical bytes, so a header.json that is not canonical is a modified file.
    if header_data != _full_canonical(header):
        raise BackupError(WRONG_FULL_BACKUP_PASSWORD)
    core = {key: value for key, value in header.items() if key != "recipient"}
    body = {key: value for key, value in recipient.items() if key != "wrapped_key"}
    return _V3Header(header=header, core=core, core_data=_full_canonical(core), recipient=recipient,
                     recipient_body=body, kdf=dict(kdf), ephemeral_public=ephemeral_public, wrapped=wrapped)


def _v3_manifest_aad(core_data: bytes) -> bytes:
    return FULL_BACKUP_V3_AAD + core_data


def _v3_member_aad(core_data: bytes, manifest_digest: bytes, member: str) -> bytes:
    return FULL_BACKUP_V3_AAD + core_data + manifest_digest + member.encode("ascii")


def _v3_open_manifest(blob: bytes, data_key: bytes | bytearray, core_data: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise BackupError("Full backup manifest is truncated")
    try:
        return AESGCM(bytes(data_key)).decrypt(blob[:12], blob[12:], _v3_manifest_aad(core_data))
    except InvalidTag:
        raise BackupError(WRONG_FULL_BACKUP_PASSWORD) from None


def _full_read_v3(
    archive: zipfile.ZipFile,
    info_by_name: dict[str, zipfile.ZipInfo],
    header_data: bytes,
    header: dict[str, Any],
    backup_password: str | SecretText | None,
    *,
    data_key: bytes | bytearray | None,
    on_entry: Callable[[dict[str, Any], bytes], None],
    cancel: Callable[[], bool] | Any | None,
    progress: Callable[..., Any] | None,
) -> dict[str, Any]:
    """The v3 branch of ``_full_read_container`` (the ZIP member checks before it are shared)."""
    from .backup_key import unwrap_with_password
    parsed = _v3_parse_header(header_data, header)
    manifest_info = info_by_name.get("manifest.bin")
    if manifest_info is None:
        raise BackupError("Missing full backup manifest")
    manifest_blob = _full_zip_read(archive, manifest_info, MAX_FULL_BACKUP_MANIFEST_BYTES + 64, cancel=cancel)
    if len(manifest_blob) < 12 + 16:
        raise BackupError("Full backup manifest is truncated")
    if data_key is not None:
        if len(data_key) != 32:
            raise BackupError(WRONG_FULL_BACKUP_PASSWORD)
        dk = bytearray(data_key)
    else:
        # Argon2 → key id check (no GCM attempt on a mismatch) → unwrap; every failure is the v2 message.
        dk = unwrap_with_password(backup_password, kdf=parsed.kdf, expected_key_id=parsed.recipient["key_id"],
                                  ephemeral_public=parsed.ephemeral_public, wrapped=parsed.wrapped,
                                  aad=parsed.wrap_aad())
    try:
        manifest_data = _v3_open_manifest(manifest_blob, dk, parsed.core_data)
        if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
            raise BackupError("Full backup manifest is too large")
        manifest = _full_validate_json_object(manifest_data, "Full backup manifest")
        entries = _full_manifest_entries(manifest, header, expected_version=FULL_BACKUP_V3_VERSION)
        expected_names = {"header.json", "manifest.bin"} | {entry["member"] for entry in entries}
        if set(info_by_name) != expected_names:
            raise BackupError("Full backup members do not match its manifest")
        manifest_digest = hashlib.sha256(manifest_data).digest()
        cipher = AESGCM(bytes(dk))
        for index, entry in enumerate(entries, start=1):
            _full_cancelled(cancel)
            info = info_by_name[entry["member"]]
            if info.file_size != entry["size"] + 12 + 16:
                raise BackupError("Full backup member size does not match its manifest")
            blob = _full_zip_read(archive, info, MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024, cancel=cancel)
            try:
                data = cipher.decrypt(blob[:12], blob[12:],
                                      _v3_member_aad(parsed.core_data, manifest_digest, entry["member"]))
            except InvalidTag:
                raise BackupError(WRONG_FULL_BACKUP_PASSWORD) from None
            if len(data) != entry["size"] or _full_sha256(data) != entry["sha256"]:
                raise BackupError("Full backup member authentication failed")
            on_entry(entry, data)
            _full_progress(progress, "import", index, len(entries))
        return {"manifest": manifest, "header": header, "entries": entries}
    finally:
        dk[:] = bytes(len(dk))


def _full_collect_entries(
    *,
    profile_dir: Path | None,
    vault_file: Path | None,
    settings_file: Path | None,
    attachment_store_dir: Path | None,
    attachment_store: Path | None,
    profile_name: str | None,
    cancel: Callable[[], bool] | Any | None,
    progress: Callable[..., Any] | None,
    vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """The profile members, read and checked exactly as ``export_full_backup`` does.  For the v3 writer only:
    the v2 writer keeps its own copy, so a change here cannot change v2 output (hard rule 1.1)."""
    root, vault_file, settings_file, attachment_dir, anchor = _full_resolve_paths(
        profile_dir=profile_dir, vault_file=vault_file, settings_file=settings_file,
        attachment_store_dir=attachment_store_dir, attachment_store=attachment_store,
    )
    _full_cancelled(cancel)
    vault_data = _full_bounded_read(vault_file, MAX_FULL_BACKUP_MEMBER_BYTES, label="Vault", cancel=cancel,
                                    progress=progress, phase="read-vault")
    vault_data = _full_filtered_vault(vault_data, vault_filter)
    settings = _full_read_settings(settings_file)
    settings_data = _full_canonical(settings)
    if len(settings_data) > MAX_FULL_BACKUP_SETTINGS_BYTES:
        raise BackupError("Profile settings are too large")
    entries: list[dict[str, Any]] = [
        {"kind": "vault", "target": "vault.json", "data": vault_data,
         "size": len(vault_data), "sha256": _full_sha256(vault_data)},
        {"kind": "settings", "target": "settings.json", "data": settings_data,
         "size": len(settings_data), "sha256": _full_sha256(settings_data)},
    ]
    if anchor.exists():
        anchor_data = _full_bounded_read(anchor, 64 * 1024, label="Vault generation metadata", cancel=cancel,
                                         progress=progress, phase="read-vault")
        _full_validate_generation(anchor_data)
        entries.append({"kind": "generation", "target": "generation.json", "data": anchor_data,
                        "size": len(anchor_data), "sha256": _full_sha256(anchor_data)})
    entries.extend(_full_source_sidecars(attachment_dir, cancel=cancel, progress=progress))
    if len(entries) > MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup contains too many entries")
    if profile_name is None:
        profile_name = root.name or "Restored profile"
    if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 256 or "\x00" in profile_name:
        raise BackupError("Profile name is malformed")
    return entries, profile_name


def _v3_recipient(core: dict[str, Any], record: dict[str, Any], data_key: bytes | bytearray,
                  ephemeral: Any, public_key: bytes) -> dict[str, Any]:
    """A recipient block for ``core`` that wraps ``data_key`` to ``record`` with ``ephemeral`` (3.4)."""
    from .backup_key import RECIPIENT_SCHEME, wrap_aad, wrap_data_key
    body = {
        "scheme": RECIPIENT_SCHEME,
        "key_id": record["key_id"],
        "key_set_at": record["set_at"],
        "kdf": dict(record["kdf"]),
        "ephemeral_public_key": _b64e(ephemeral.public),
    }
    wrapped = wrap_data_key(data_key, public_key, ephemeral, wrap_aad(core, body))
    return {**body, "wrapped_key": _b64e(wrapped)}


def _v3_read_header_only(path: Path) -> tuple[bytes, Any]:
    """``header.json`` of a ZIP, without reading any other member.  Raises ``BackupError``."""
    path = Path(path)
    _full_regular_file(path, "Full backup")
    try:
        if path.stat().st_size > MAX_FULL_BACKUP_BYTES:
            raise BackupError("Full backup is too large")
        with zipfile.ZipFile(path, "r") as archive:
            try:
                info = archive.getinfo("header.json")
            except KeyError:
                raise BackupError("Missing full backup header") from None
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                raise BackupError("Full backup compression or ZIP encryption is unsupported")
            header_data = _full_zip_read(archive, info, MAX_FULL_BACKUP_HEADER_BYTES)
    except BackupError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise BackupError("Could not read full backup") from exc
    return header_data, _full_validate_json_object(header_data, "Full backup header")


def _v3_verify_written(path: Path, *, data_key: bytes | bytearray, ephemeral: Any, public_key: bytes,
                       key_id_value: str) -> _V3Header:
    """9.1 steps 1 and 2: the structure, then the wrap opens for ``public_key``'s private key (shown with ``esk``:
    ``X25519(esk, 9) == epk``, ``key_id`` matches, and GCM-open with ``kek`` from ``X25519(esk, pk)`` gives ``dk``)."""
    from .backup_key import WRAP_NONCE, _shared_secret, _wrap_kek, key_id, x25519_public
    from .backup_schedule import ensure_encrypted_container
    try:
        ensure_encrypted_container(path)
    except Exception as exc:  # noqa: BLE001 - ScheduleError is not a BackupError
        raise BackupError("The written backup is not an encrypted full-backup container") from exc
    header_data, header = _v3_read_header_only(path)
    parsed = _v3_parse_header(header_data, header)
    failed = BackupError("The written backup does not open with the backup key")
    if (not hmac.compare_digest(x25519_public(ephemeral.secret), parsed.ephemeral_public)
            or not hmac.compare_digest(parsed.recipient["key_id"], key_id_value)
            or not hmac.compare_digest(key_id(public_key), key_id_value)):
        raise failed
    shared = kek = opened = bytearray()
    try:
        try:
            shared = _shared_secret(ephemeral.secret, public_key)
        except ValueError:
            raise failed from None
        kek = _wrap_kek(shared, parsed.ephemeral_public, public_key)
        try:
            opened = bytearray(AESGCM(bytes(kek)).decrypt(WRAP_NONCE, parsed.wrapped, parsed.wrap_aad()))
        except InvalidTag:
            raise failed from None
        if not hmac.compare_digest(bytes(opened), bytes(data_key)):
            raise failed
    finally:
        for buffer in (shared, kek, opened):
            buffer[:] = bytes(len(buffer))
    return parsed


def _v3_content_check(path: Path, data_key: bytes | bytearray, *,
                      cancel: Callable[[], bool] | Any | None = None) -> dict[str, Any]:
    """9.1 step 3: the restore preflight dry run (manifest, every member's tag, size and SHA-256, the staged vault
    structure), given the data key instead of a password."""
    # Staged in the owner-only data folder, never beside the file: the file may sit in a mirror (cloud) folder,
    # and the dry run writes the backup's outer layer (settings.json and the sidecars) in clear (review L7).
    with private_temporary_directory("lgk-scheduled-probe-") as probe:
        return _restore_full_backup(Path(path), profile_dir=Path(probe) / "profile", backup_password=None,
                                    dry_run=True, cancel=cancel, _data_key=data_key,
                                    _stage_parent=Path(probe) / "stage")


def _v3_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class KeyBackupVerifier:
    """Section 9.1: checks a just-written v3 file without any password.

    Holds the file's data key and ephemeral secret until ``wipe()`` (or the end of a ``with`` block).  Internal
    only: never exposed in the UI.  ``verify(path)`` raises ``BackupError`` or returns
    ``{"sha256": <hex of the file>, "preflight": <dry-run info>}``; the scheduler stores the digest as
    ``last_sha256`` (step 4) and compares the mirror copy with it.
    """

    def __init__(self, *, data_key: bytearray, ephemeral: Any, public_key: bytes, key_id: str) -> None:
        self._data_key = data_key
        self._ephemeral = ephemeral
        self._public_key = bytes(public_key)
        self.key_id = key_id

    def __enter__(self) -> KeyBackupVerifier:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.wipe()

    def wipe(self) -> None:
        self._data_key[:] = bytes(len(self._data_key))
        self._ephemeral.wipe()

    def verify(self, path: Path, *, record: dict[str, Any] | None = None,
               cancel: Callable[[], bool] | Any | None = None) -> dict[str, Any]:
        """Steps 1-4.  ``record`` (optional) is the record as stored now; the file must be wrapped to its public
        key (a record swapped between make and verify fails step 2)."""
        from .backup_key import record_public_key
        path = Path(path)
        if not any(self._data_key):
            raise BackupError("The backup verifier has been wiped")
        public_key, key_id_value = self._public_key, self.key_id
        if record is not None:
            public_key, key_id_value = record_public_key(record), record["key_id"]
        _v3_verify_written(path, data_key=self._data_key, ephemeral=self._ephemeral, public_key=public_key,
                           key_id_value=key_id_value)
        preflight = _v3_content_check(path, self._data_key, cancel=cancel)
        return {"sha256": _v3_file_sha256(path), "preflight": preflight}


def export_full_backup_to_key(
    destination: Path,
    *,
    record: dict[str, Any],
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    attachment_store: Path | None = None,
    profile_name: str | None = None,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write a full backup v3 to the public key of a backup key ``record`` (3.3) and return its summary.

    ``vault_filter``: what the vault file becomes in the backup (``without_share_records``).

    The result's ``"verifier"`` is a ``KeyBackupVerifier`` holding ``dk`` and ``esk``: call ``verify(path)`` and
    then ``wipe()`` (or use it in a ``with`` block).  It is wiped already if this raises.  Random bytes are taken
    in this order (the vectors replay them): ``dk`` (32), ``esk`` (32), the manifest nonce (12), then one nonce
    (12) per member.  ``created_at`` in the manifest is ``int(time.time())``, as in v2.
    """
    from .backup_key import new_ephemeral_key, record_public_key, validate_record
    record = validate_record(record)
    public_key = record_public_key(record)
    entries, profile_name = _full_collect_entries(
        profile_dir=profile_dir, vault_file=vault_file, settings_file=settings_file,
        attachment_store_dir=attachment_store_dir, attachment_store=attachment_store, profile_name=profile_name,
        cancel=cancel, progress=progress, vault_filter=vault_filter,
    )
    data_key = bytearray(os.urandom(32))
    ephemeral = new_ephemeral_key()
    verifier = KeyBackupVerifier(data_key=data_key, ephemeral=ephemeral, public_key=public_key,
                                 key_id=record["key_id"])
    try:
        core = {"format": FULL_BACKUP_FORMAT, "version": FULL_BACKUP_V3_VERSION, "cipher": dict(FULL_BACKUP_CIPHER),
                "entry_count": len(entries)}
        header = {**core, "recipient": _v3_recipient(core, record, data_key, ephemeral, public_key)}
        header_data = _full_canonical(header)
        core_data = _full_canonical(core)
        if len(header_data) > MAX_FULL_BACKUP_HEADER_BYTES:
            raise BackupError("Full backup header is too large")
        manifest_entries: list[dict[str, Any]] = []
        for index, entry in enumerate(entries):
            member = f"data/{index:08d}.bin"
            entry["member"] = member
            row = {key: entry[key] for key in ("kind", "target", "size", "sha256")}
            if entry["kind"] == "attachment":
                row["attachment_id"] = entry["attachment_id"]
                row["sidecar_size"] = entry["sidecar_size"]
            row["member"] = member
            manifest_entries.append(row)
        manifest = {"version": FULL_BACKUP_V3_VERSION, "profile_name": profile_name, "entries": manifest_entries,
                    "created_at": int(time.time())}
        manifest_data = _full_canonical(manifest)
        if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
            raise BackupError("Full backup manifest is too large")
        manifest_digest = hashlib.sha256(manifest_data).digest()
        key = bytes(data_key)
        manifest_blob = _full_encrypt(manifest_data, key=key, aad=_v3_manifest_aad(core_data))

        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_dir():
            raise BackupError("Backup destination must be a file")
        fd, name = tempfile.mkstemp(prefix=".lgk-full-backup-", suffix=".tmp", dir=destination.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w+b") as handle:
                with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                    archive.writestr(_full_zip_info("header.json"), header_data)
                    archive.writestr(_full_zip_info("manifest.bin"), manifest_blob)
                    total = len(entries)
                    for index, entry in enumerate(entries, start=1):
                        _full_cancelled(cancel)
                        data = _full_entry_bytes(entry, cancel=cancel, progress=progress)
                        blob = _full_encrypt(data, key=key,
                                             aad=_v3_member_aad(core_data, manifest_digest, entry["member"]))
                        archive.writestr(_full_zip_info(entry["member"]), blob)
                        _full_progress(progress, "export", index, total)
                handle.flush()
                os.fsync(handle.fileno())
            if temporary.stat().st_size > MAX_FULL_BACKUP_BYTES:
                raise BackupError("Full backup is too large")
            _full_cancelled(cancel)
            os.replace(temporary, destination)
        except BackupError:
            temporary.unlink(missing_ok=True)
            raise
        except (OSError, zipfile.BadZipFile, ValueError) as exc:
            temporary.unlink(missing_ok=True)
            raise BackupError("Could not write full backup") from exc
    except BaseException:
        verifier.wipe()
        raise
    return {
        "version": FULL_BACKUP_V3_VERSION,
        "profile_name": profile_name,
        "entries": len(entries),
        "attachments": sum(entry["kind"] == "attachment" for entry in entries),
        "bytes": destination.stat().st_size,
        "key_id": record["key_id"],
        "verifier": verifier,
    }


def relock_full_backup(path: Path, *, old_key: Any, new_record: dict[str, Any]) -> str:
    """Section 7.2: re-wrap one v3 backup's data key from ``old_key`` (a ``backup_key.BackupKey`` derived from the
    old password) to ``new_record``.  Returns ``RELOCK_RELOCKED``, or, without opening anything but
    ``header.json`` and without touching the file, ``RELOCK_OLD_FORMAT`` (not version 3: v1/v2 or unreadable) or
    ``RELOCK_OTHER_KEY`` (made by another key).

    Only ``header.json`` changes; every other member is copied byte for byte (same names, same order).  The new
    file is verified (9.1 steps 1-3 with ``dk``), replaced onto the same name and given the original mtime.  The
    outer layer only: ``vault.json`` is never decrypted.  On failure the original is kept (``BackupError``).
    """
    from .backup_key import new_ephemeral_key, record_public_key, unwrap_data_key, validate_record
    path = Path(path)
    new_record = validate_record(new_record)
    new_public = record_public_key(new_record)
    try:
        header_data, header = _v3_read_header_only(path)
    except BackupError:
        return RELOCK_OLD_FORMAT
    if (not isinstance(header, dict) or header.get("format") != FULL_BACKUP_FORMAT
            or type(header.get("version")) is not int or header.get("version") != FULL_BACKUP_V3_VERSION):
        return RELOCK_OLD_FORMAT
    parsed = _v3_parse_header(header_data, header)
    if not hmac.compare_digest(parsed.recipient["key_id"], old_key.key_id):
        return RELOCK_OTHER_KEY
    data_key = unwrap_data_key(old_key.private_key, parsed.ephemeral_public, parsed.wrapped, parsed.wrap_aad())
    ephemeral = new_ephemeral_key()
    temporary: Path | None = None
    try:
        original = path.stat()
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(set(names)) != len(names) or "manifest.bin" not in names:
                raise BackupError("Full backup contains an unsafe archive member")
            _v3_open_manifest(_full_zip_read(archive, archive.getinfo("manifest.bin"),
                                             MAX_FULL_BACKUP_MANIFEST_BYTES + 64), data_key, parsed.core_data)
            new_header = {**parsed.core,
                          "recipient": _v3_recipient(parsed.core, new_record, data_key, ephemeral, new_public)}
            new_header_data = _full_canonical(new_header)
            fd, name = tempfile.mkstemp(prefix=".lgk-relock-", suffix=".tmp", dir=path.parent)
            temporary = Path(name)
            with os.fdopen(fd, "w+b") as handle:
                with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as out:
                    out.writestr(_full_zip_info("header.json"), new_header_data)
                    for info in infos:
                        if info.filename == "header.json":
                            continue
                        if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                            raise BackupError("Full backup compression or ZIP encryption is unsupported")
                        out.writestr(_full_zip_info(info.filename),
                                     _full_zip_read(archive, info, MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024))
                handle.flush()
                os.fsync(handle.fileno())
        _v3_verify_written(temporary, data_key=data_key, ephemeral=ephemeral, public_key=new_public,
                           key_id_value=new_record["key_id"])
        _v3_content_check(temporary, data_key)
        os.replace(temporary, path)
        temporary = None
        try:
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        except OSError as exc:  # re-locked all the same; only the retention date may now differ (L4)
            import logging
            logging.getLogger(__name__).warning("Re-locked backup kept a new modified time: %s", exc)
        return RELOCK_RELOCKED
    except BackupError:
        raise
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise BackupError("Could not re-lock the backup") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        data_key[:] = bytes(len(data_key))
        ephemeral.wipe()


def relock_full_backups(paths: list[Path], *, old_key: Any, new_record: dict[str, Any]) -> dict[str, Any]:
    """Re-lock each of ``paths`` (the caller lists them: ``owned_backups`` of the scheduled and mirror folders).

    Returns ``{"relocked": [...], "left": [...], "failed": [(path, message), ...]}``.  ``left`` (the "M older
    backups" of 7.2) holds old-format files and files under other keys; only their ``header.json`` was read.
    One failure never stops the others.
    """
    relocked: list[Path] = []
    left: list[Path] = []
    failed: list[tuple[Path, str]] = []
    for path in paths:
        try:
            status = relock_full_backup(Path(path), old_key=old_key, new_record=new_record)
        except BackupError as exc:
            failed.append((Path(path), str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 - e.g. the file vanished (pruned, cloud sync): never stop (L4)
            failed.append((Path(path), f"Could not re-lock the backup ({type(exc).__name__})"))
            continue
        (relocked if status == RELOCK_RELOCKED else left).append(Path(path))
    return {"relocked": relocked, "left": left, "failed": failed}


RELOCK_LEFTOVER_AGE_SECONDS = 600


def sweep_relock_leftovers(folder: Path, *, now: float | None = None) -> list[Path]:
    """Remove what an interrupted re-lock or scheduled check left in ``folder`` (review L7).

    Only this app's own scratch names older than ``RELOCK_LEFTOVER_AGE_SECONDS``: ``.lgk-relock-*.tmp`` files
    (encrypted copies) and ``.lgk-scheduled-probe-*`` folders (an earlier release staged its dry run there).
    Backups are never touched.
    """
    import time

    removed: list[Path] = []
    limit = (time.time() if now is None else now) - RELOCK_LEFTOVER_AGE_SECONDS
    try:
        children = list(Path(folder).iterdir())
    except OSError:
        return removed
    for child in children:
        name = child.name
        try:
            if child.is_symlink() or child.stat().st_mtime > limit:
                continue
            if name.startswith(".lgk-relock-") and name.endswith(".tmp") and child.is_file():
                child.unlink()
            elif name.startswith(".lgk-scheduled-probe-") and child.is_dir() and not child.is_junction():
                shutil.rmtree(child)
            else:
                continue
        except OSError:
            continue
        removed.append(child)
    return removed


def is_version3_backup(path: Path) -> bool:
    """True when ``path``'s cleartext ``header.json`` says full backup version 3 (no other member is read).

    Anything unreadable is not version 3, so callers that protect old-format files keep it (fail closed).
    """
    try:
        _header_data, header = _v3_read_header_only(Path(path))
    except BackupError:
        return False
    return (isinstance(header, dict) and header.get("format") == FULL_BACKUP_FORMAT
            and type(header.get("version")) is int and header.get("version") == FULL_BACKUP_V3_VERSION)


_SCHEDULED_NAME_TIME = r"^LocalGateKeys-scheduled-[0-9a-f]{8}-(\d{8}-\d{6})(?:-\d{1,3})?\.lgk$"


def _old_format_date(path: Path) -> tuple[int, str]:
    """The scheduled-filename timestamp (local time) when the name matches, else the file's modified time."""
    import re
    from datetime import datetime
    match = re.match(_SCHEDULED_NAME_TIME, path.name, re.IGNORECASE)
    if match:
        try:
            return int(datetime.strptime(match.group(1), "%Y%m%d-%H%M%S").timestamp()), "filename"
        except (ValueError, OverflowError, OSError):
            pass
    return int(path.stat().st_mtime), "modified"


def describe_backup(source: Path, *, record: dict[str, Any] | None = None) -> dict[str, Any]:
    """The restore screen's key line (section 8), from the cleartext header only (no password, no decryption).

    Returns ``format_kind`` (``"full"`` or ``"catalog"``), ``version`` and ``key_line``:

    * v3: ``key_id``, ``key_set_at`` and ``key_line`` = ``"current"`` (the device ``record``'s key),
      ``"earlier_changed"`` (in its history; ``replaced_at``), ``"earlier_reset"`` (replaced by a reset;
      ``reset_at``) or ``"other_device"`` (unknown here, or no record given).
    * full v2 and vault-only ``.lgk`` v1/v2: ``key_line = "old_format"`` ("uses the backup password that was in
      use when it was made"), with ``date`` and ``date_source`` (``"filename"`` for a scheduled name, else
      ``"modified"``).

    All times are integer Unix seconds; the UI formats them.  Raises ``BackupError`` for anything unreadable.
    """
    from .backup_key import validate_record
    path = Path(source)
    _full_regular_file(path, "Backup")
    try:
        with path.open("rb") as handle:
            prefix = handle.read(4)
    except OSError as exc:
        raise BackupError("Could not read this backup") from exc
    if prefix.startswith(b"PK\x03\x04"):
        header_data, header = _v3_read_header_only(path)
        version = header.get("version")
        if header.get("format") == FULL_BACKUP_FORMAT and type(version) is int and version == FULL_BACKUP_VERSION:
            date, date_source = _old_format_date(path)
            return {"format_kind": "full", "version": FULL_BACKUP_VERSION, "key_line": "old_format", "date": date,
                    "date_source": date_source}
        parsed = _v3_parse_header(header_data, header)
        found = parsed.recipient["key_id"]
        result: dict[str, Any] = {"format_kind": "full", "version": FULL_BACKUP_V3_VERSION, "key_id": found,
                                  "key_set_at": parsed.recipient["key_set_at"], "key_line": "other_device"}
        if record is not None:
            current = validate_record(record)
            if current["key_id"] == found:
                result["key_line"] = "current"
            else:
                newer: dict[str, Any] = current   # the key that replaced each history entry
                for entry in current["history"]:
                    if entry["key_id"] == found:
                        if newer["set_by"] == "reset":
                            result.update(key_line="earlier_reset", reset_at=entry["replaced_at"])
                        else:
                            result.update(key_line="earlier_changed", replaced_at=entry["replaced_at"])
                        break
                    newer = entry
        return result
    try:
        if path.stat().st_size > MAX_BACKUP_BYTES:
            raise BackupError("Backup is too large")
        with path.open("rb") as handle:
            envelope = json.loads(handle.read(MAX_BACKUP_BYTES + 1))
    except BackupError:
        raise
    except (OSError, ValueError, RecursionError):
        raise BackupError("Could not read this backup") from None
    version = envelope.get("version") if isinstance(envelope, dict) else None
    if (not isinstance(envelope, dict) or envelope.get("format") != "localgatekeys-backup"
            or type(version) is not int or version not in SUPPORTED_BACKUP_VERSIONS):
        raise BackupError("Unsupported backup format")
    date, date_source = _old_format_date(path)
    return {"format_kind": "catalog", "version": version, "key_line": "old_format", "date": date,
            "date_source": date_source}


# --------------------------------------------------------------------------- restore test (sub-plan 12)


@dataclasses.dataclass(frozen=True)
class RestoredVault:
    """What a scratch restore proved: the backup opened and its vault unlocked. No secret is kept."""

    profile_name: str
    items: int
    exported_at: int


class RestoreTestFailure(BackupError):
    """``reason`` is ``"unreadable"`` (damaged or not a backup) or ``"old_password"`` (the password did not open it)."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def restore_to_scratch(path: Path, password: str | SecretText, scratch: Path, *,
                       vault_password: str | SecretText | None = None) -> RestoredVault:
    """Restore the ``.lgk`` backup at ``path`` into ``scratch`` (never the live vault) and unlock it once.

    ``password`` is the backup password; ``vault_password`` the vault master password (defaults to ``password``).
    The caller owns ``scratch`` and deletes it.
    """
    from .vault import VaultError

    try:
        payload = _read_backup_payload(Path(path), password)  # type: ignore[arg-type]
    except BackupError as exc:
        reason = "old_password" if "password" in str(exc).lower() else "unreadable"
        raise RestoreTestFailure(reason, str(exc)) from None
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    vault_path = scratch / "vault.json"
    atomic_write_json(vault_path, payload["vault"])
    secret, owned = _vault_secret(password if vault_password is None else vault_password, _VERIFY_FAILED)
    try:
        session = _open_backup_vault(vault_path, secret, upgrade_envelope=False)
    except VAULT_PROMPT_ERRORS as exc:
        raise RestoreTestFailure("old_password", str(exc)) from None
    except (VaultError, OSError, ValueError, TypeError, OverflowError):
        raise RestoreTestFailure("old_password", _VERIFY_FAILED) from None
    finally:
        if owned:
            secret.wipe()
    try:
        return RestoredVault(profile_name=str(payload.get("profile_name") or "Restored profile"),
                             items=len(session.summaries()), exported_at=int(payload.get("exported_at", 0)))
    finally:
        session.lock()
