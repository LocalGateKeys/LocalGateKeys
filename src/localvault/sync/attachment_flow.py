"""Moving document files during a sync run (folder and Wi-Fi); format in ``attachment_sync``.

* ``import_missing``: before ``run_merge``, every live document in the peer views whose file this
  vault lacks is fetched (``fetch(ref) -> blob | None``), verified and stored.  A document whose
  file is still missing is then set aside by ``apply`` (``attachment-missing``) and retried on the
  next run; a refused (tampered) blob gives ``attachment-refused`` and stores nothing.
* Folder capability (publish gating): ``attachments/<device_id>.lgkcap`` is a zero-record
  format-1 view of the current epoch, signed like a view (``attachments/<device_id>.lgkcap.lgksig``).
  It counts only when it decodes under the group key, names that device, and its signature
  verifies with the key this device trusts for it.  Anything else is "not capable".
* ``publish_folder_blobs``: before the own view is written, the blob of every own document that
  is not in the folder yet is written (content addressed, never rewritten).
"""
from __future__ import annotations

import base64
import os
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from ..attachments import AttachmentError, AttachmentStore
from .attachment_sync import BLOBS_DIR_NAME, MAX_ATTACHMENTS, AttachmentRef, BlobFolder
from .engine import ItemState
from .group import MAX_SIG_BYTES, GroupKey, decode_view, encode_view, sign_view, verify_view_signature
from .runner import SyncIssue
from .vault_bridge import _check_lease, document_refs, remember_blob, sync_only_save

CAP_SUFFIX = ".lgkcap"
CAP_SIG_SUFFIX = ".lgkcap.lgksig"
MAX_CAP_BYTES = 4096


def _present(store: AttachmentStore) -> set[str]:
    out = set()
    for row in store._payload().get("attachments", []) or []:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            try:
                path = store._path(row["id"])
            except AttachmentError:
                continue
            if path.is_file() and not path.is_symlink():
                out.add(row["id"])
    return out


def unique_refs(refs: Iterable[AttachmentRef]) -> tuple[list[AttachmentRef], list[SyncIssue]]:
    """One reference per attachment id (a conflicting second one is dropped), at most ``MAX_ATTACHMENTS``."""
    seen: dict[str, AttachmentRef] = {}
    issues: list[SyncIssue] = []
    for ref in refs:
        known = seen.get(ref.attachment_id)
        if known is None:
            if len(seen) >= MAX_ATTACHMENTS:
                issues.append(SyncIssue("too-many-attachments", str(MAX_ATTACHMENTS)))
                break
            seen[ref.attachment_id] = ref
        elif known != ref:
            issues.append(SyncIssue("attachment-refused", f"{ref.attachment_id}: two different files"))
    return list(seen.values()), issues


def import_missing(session: Any, lease: Any, states: Iterable[ItemState],
                   fetch: Callable[[AttachmentRef], bytes | None]) -> list[SyncIssue]:
    refs, issues = unique_refs(document_refs(states))
    if not refs:
        return issues
    store = AttachmentStore(session)
    have = _present(store)
    for ref in sorted(refs, key=lambda r: r.blob):
        if ref.attachment_id in have:
            continue
        blob = fetch(ref)
        if blob is None:
            continue  # apply reports attachment-missing for the document
        _check_lease(session, lease)
        try:
            with sync_only_save(session):
                store.import_sync_blob(ref, blob)
        except AttachmentError as exc:
            issues.append(SyncIssue("attachment-refused", f"{ref.attachment_id}: {exc}"))
            continue
        remember_blob(ref.catalog_record(), ref.blob, ref.blob_size)
    return issues


def own_blob(session: Any, ref: AttachmentRef) -> bytes | None:
    """The blob of one of this vault's attachments when it matches *ref*, else None."""
    try:
        ref_dict, blob = AttachmentStore(session).export_sync_blob(ref.attachment_id)
    except AttachmentError:
        return None
    return blob if ref_dict["blob"] == ref.blob else None


# --- folder --------------------------------------------------------------------------------


def _cap_paths(sync_dir: Path, device_id: str) -> tuple[Path, Path]:
    folder = Path(sync_dir) / BLOBS_DIR_NAME
    cap, sig = folder / f"{device_id}{CAP_SUFFIX}", folder / f"{device_id}{CAP_SIG_SUFFIX}"
    if cap.parent != folder or sig.parent != folder or cap.name != f"{device_id}{CAP_SUFFIX}":
        raise ValueError("capability file escapes the attachments folder")
    return cap, sig


def _read_small(path: Path, limit: int) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def folder_capable(sync_dir: Path, gk: GroupKey, device_id: str, signer: str | None) -> bool:
    """Whether *device_id* published a valid signed capability file under *gk* (see the module docstring)."""
    if signer is None:
        return False
    try:
        cap_path, sig_path = _cap_paths(sync_dir, device_id)
    except ValueError:
        return False
    raw, sig = _read_small(cap_path, MAX_CAP_BYTES), _read_small(sig_path, MAX_SIG_BYTES)
    if raw is None or sig is None:
        return False
    try:
        view = decode_view(gk, raw, expected_device_id=device_id, max_bytes=MAX_CAP_BYTES, max_records=0)
        public = base64.b64encode(verify_view_signature(sig, raw, view.header)).decode("ascii")
    except ValueError:
        return False
    return public == signer


def _atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_capability(sync_dir: Path, gk: GroupKey, device_id: str, signing_key: ed25519.Ed25519PrivateKey,
                     signer: str, *, now: int) -> bool:
    """Write this device's capability file unless a valid one is there; whether it wrote."""
    if folder_capable(sync_dir, gk, device_id, signer):
        return False
    cap_path, sig_path = _cap_paths(sync_dir, device_id)
    raw = encode_view(gk, device_id, 0, (), now)
    cap_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic(cap_path, raw)
    _atomic(sig_path, sign_view(raw, signing_key))
    return True


def publish_folder_blobs(session: Any, folder: BlobFolder, own_states: Iterable[ItemState], *,
                         now: float | None = None) -> list[SyncIssue]:
    """Write the blob of every own document missing from the folder (before the view is written).

    A blob already there is kept when its length is right (its time is refreshed so a concurrent
    sweep leaves it); a truncated or wrong-length one (a half-synced cloud copy) is rewritten.
    """
    issues: list[SyncIssue] = []
    now = time.time() if now is None else now
    present = folder.ids()
    done: set[str] = set()
    for ref in document_refs(own_states):
        if ref.blob in done:
            continue
        exists = ref.blob in present
        if exists and folder.keep(ref.blob, ref.blob_size, now=now):
            done.add(ref.blob)
            continue
        blob = own_blob(session, ref)
        if blob is None:
            issues.append(SyncIssue("attachment-missing", f"own:{ref.attachment_id}"))
            continue
        try:
            folder.write(blob, replace=exists)
        except (OSError, ValueError) as exc:
            issues.append(SyncIssue("write-failed", f"attachment: {exc}"))
            continue
        done.add(ref.blob)
    return issues


def referenced_blobs(state_sets: Iterable[Iterable[ItemState]]) -> set[str]:
    out: set[str] = set()
    for states in state_sets:
        out |= {ref.blob for ref in document_refs(states)}
    return out


def signers_for(mapping: Mapping[str, str], device_id: str) -> str | None:
    value = mapping.get(device_id)
    return value if isinstance(value, str) else None
