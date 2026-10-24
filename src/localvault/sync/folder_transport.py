"""Cloud-folder sync transport: encrypted device files in a user-chosen folder.

Layout (inside the folder the user picks: OneDrive, Dropbox, iCloud Drive...)::

    <root>/LocalGateKeys Sync/
      keyring.lgkkeys              group keyring (``keyring.py``), atomic writes
      devices/<device_id>.lgksync  one sealed view per device (``group.py``)
      signatures/<device_id>.lgksig  the writer's Ed25519 signature of that view

Each device writes only its own file and reads everyone else's.  The cloud
provider sees ciphertext, file names (device ids), sizes and timestamps.

One run (``FolderSync.run_once``)
---------------------------------
1. The vault must be unlocked (lease), joined (``SyncGroupState``) and bound to
   this installation: a stored ``install_id`` different from the caller's
   (vault copied or restored onto another PC) gives ``rejoin-required`` and
   nothing is read or written.  ``install_id`` must be a non-empty string of at
   most ``MAX_INSTALL_ID`` characters everywhere (``bad-install-id``).
2. Missing folder -> ``folder-missing``; the vault is not touched.
3. Keyring trust: ``accept_keyring`` against the stored ``(group_id, epoch,
   G)`` on every run.  Epoch + 1 is adopted and persisted at once, and the
   bytes of every accepted keyring are kept in ``SyncGroupState.keyring``.
   When the folder's keyring is ``rollback`` or ``tampered`` (same group;
   including an unopenable device wrap or a member key that differs from ours),
   the stored keyring is verified again and written back atomically
   (``keyring-restored``) and the run continues with the trusted key.  This
   undoes a join that raced a rotation (the joiner wrote the old epoch over the
   new one) and an attacker replaying an old keyring.  Without a stored
   keyring, or if writing it back fails, the run stops with the original kind.
   A keyring of ANOTHER group is never overwritten: the run stops with
   ``folder-has-other-group`` and writes nothing (neither keyring nor own
   file), because two groups sharing one folder (e.g. the folder was emptied
   and a new group created while this device was offline) would otherwise
   overwrite each other's keyring forever; the user leaves or re-joins.
   A keyring at the trusted epoch whose MAC fails under the stored key but
   that opens with this device's own wrap and verifies under that wrapped key
   is a competing rotation (two members rotated from the same epoch): the run
   stops with ``rotation-conflict``, restores nothing and writes nothing, and
   the user re-joins with the newest sync password (``join_folder_group``
   allows it).  Restoring there would make the two rotators overwrite each
   other on every run and split the group.  The same keyring that does not
   list this device (or lacks its wrap) stops with ``removed-or-conflict`` and
   writes nothing: a rotation that removed this device may have overlapped
   another rotation, and restoring would undo the removal.  A keyring is never
   restored over a newer epoch: at the trusted epoch + 1, a keyring that does
   not chain from the stored key (or whose wrap fails) stops with
   ``rotation-conflict`` (``removed-or-conflict`` if this device is not
   listed), so the winner of an earlier conflict rotating again cannot start a
   ping-pong.  Keyring temp files older than an hour (a writer that crashed)
   are deleted.
   ``missed-rotation`` and ``not-member`` stop with
   ``rejoin-required``; any other malformed keyring is ``keyring-corrupt``
   (``keyring-missing`` if absent).
4. Member tracking: member ids seen at the current epoch are kept in the vault;
   one that disappears without a rotation (anyone holding ``G`` can rewrite the
   keyring at the same epoch) gives ``member-dropped`` on every run until the
   next rotation, including when this device itself was dropped.  A member
   whose id is not a safe file name (``is_safe_device_id``: no ``:``, no
   reserved DOS name, no leading dot, no trailing dot or space) gives
   ``unsafe-member`` and its file is never read.  A member of the accepted
   keyring whose encrypted name does not decrypt under the group key gives
   ``bad-name`` (detail: its device id) on every run; the run continues and
   the screen shows it as "Unnamed device".
   Additions (audit M10): a member of the accepted keyring that this device did
   not know at its last run (``state.members``) and is not this device was added
   elsewhere (at the same epoch: anyone holding ``G`` can add one).  Its id is
   kept in ``SyncGroupState.unacked_members`` and reported as ``member-added``
   on every run until the user acknowledges it (``acknowledge_members``), it
   leaves the keyring, or this device rotates (``rotate_folder_group`` wraps the
   new key only to the confirmed keep-list).  ``old-key-known`` is reported while
   ``SyncGroupState.lan_removed`` is set (a removed Wi-Fi peer still holds ``G``).
5. Peer files (``read_peers``): only ``<id>.lgksync`` where ``id`` is a safe
   member id seen at this epoch.  Everything else (provider conflict copies
   such as ``<id> (1).lgksync`` or ``<id>-DESKTOP-ABC.lgksync``, unknown files,
   files of non-members) is counted in one ``ignored-file`` issue that lists at
   most 20 names; hidden ``.*.tmp`` files (in-flight atomic writes) are skipped
   silently, and this device's own leftover temp files are deleted.  Every file
   is decoded with ``expected_device_id``.  Per-file issues never stop the run:
   ``epoch-mismatch`` (written under another epoch; ignored until that device
   rewrites), ``device-mismatch`` (a file under another device's name),
   ``corrupt`` (truncated, garbage, failed authentication, over the bounds of
   ``group.py``), ``unreadable`` (I/O error), ``rollback`` (counter lower than
   the last one accepted from that device), ``suspicious-rewrite`` (same
   counter, different bytes; the sha256 of the last accepted file is kept per
   device) and ``stale-device``.
   Counter bounds (audit M-7): a first file of a device (no last-seen counter,
   e.g. after a rotation) above ``MAX_FILE_COUNTER`` (2**40), or a counter more
   than ``MAX_COUNTER_JUMP`` (2**24) above the last one accepted, is
   ``implausible-counter`` and skipped: the device's own next write could
   otherwise never get past it.
   Signatures (audit M-7): every view written by this version carries a
   signature file (``group.sign_view``).  A peer whose signed view verified once
   is pinned (``SyncGroupState.view_signers``, key kept per device id); from
   then on its view needs a valid signature by that key, else it is skipped as
   ``view-unsigned`` (no signature for this write: in flight, or written by
   someone else) or ``view-forged`` (a signature for this counter that does not
   match the file, or another key).  A LAN-paired peer's signing key (pinned by
   its QR pairing) is the only key its signature may carry.  Views of devices
   that never signed (older apps, the iPhone TestFlight build) are accepted
   unsigned, as before.
6. Stale files: a peer file whose header ``written_at`` is more than
   ``TOMBSTONE_MAX_AGE_DAYS`` (365) days before ``now`` is skipped ENTIRELY
   (live states and tombstones).  Its owner has not written for a year, so
   everything it holds was merged long ago; skipping it avoids resurrecting
   items whose tombstones expired.  A running device rewrites its own file at
   least every ``OWN_REFRESH_DAYS`` (30) days even without changes, so only a
   device that has not run for a year goes stale.  Such a device reports
   ``stale-self`` as a warning and runs normally (merges, then republishes,
   which makes it fresh again), so a group whose devices all went stale
   recovers on its next runs.  Documented v1 limitation: its file can bring
   back items deleted more than 365 days ago (their tombstones expired).
7. ``runner.run_merge`` merges the accepted views and applies them once.
8. The own file is written when it is missing, unreadable, at another epoch,
   not the last counter this device reserved, older than the refresh interval,
   or different from the post-apply view.  The counter is ``max(reserved, own
   file's authenticated counter) + 1`` and is persisted in the vault BEFORE the
   file is written (temp file in the same directory, flush, fsync,
   ``os.replace`` retried a few times on ``PermissionError`` because sync
   clients briefly lock files), so a crash can skip a counter but never reuse
   one.  Failure to write gives ``write-failed``.  An own file whose
   authenticated counter is above the reserved one (the vault was restored
   from an older backup) is reported once as ``counter-resynced``: the write
   in that run moves the reserved counter past it.  If that file is NOT signed
   by this device (or, once this device signs, an unsigned file at the
   reserved counter), someone else wrote it: ``own-file-rewritten`` (warning),
   the file is rewritten and signed, and its counter is moved past only when
   it is within ``MAX_COUNTER_JUMP`` of the reserved one (peers accepted it).
   An own file without a valid own signature is always rewritten.  A counter
   that cannot be incremented any more is ``counter-exhausted`` (nothing is
   written; never raises).
9. Adopting a new epoch (here or by ``rotate_folder_group``) clears every
   peer's last-seen counter, digest and signing key: only members of the new
   epoch can write files for it, so a counter or key forged under the old key
   by a removed member stops mattering.

Joining, creating, rotating, leaving
------------------------------------
``create_folder_group``, ``join_folder_group``, ``rotate_folder_group`` and
``leave_folder_group`` are the UI entry points; they raise ``FolderSyncError``
with a stable ``reason`` (a ``KeyringError`` keeps its reason, a weak password
is ``weak-password``, an I/O error is ``folder-error``; the original exception
is the ``__cause__``).  Create and join always make a fresh device identity.
Join and rotate re-read the keyring bytes immediately before writing and abort
with ``keyring-changed`` if another device wrote it meanwhile; a write that
still slips through that window is undone by the restore rule above.

A Wi-Fi-only group (``folder_path`` None, no keyring) gets a folder with
``add_folder_to_group`` (a first keyring for the stored group key, under a new
sync password) on one device and ``attach_folder`` (the folder's sync password)
on the others.  Both keep this device's identity, LAN peers, last-seen counters
and hello counter, and set ``folder_path``, ``members``, ``members_epoch`` and
``keyring``.  ``add_folder_to_group`` on a folder that already holds the same
group attaches instead; a folder of another group is ``folder-has-other-group``
and is never written.  Other refusals: ``not-joined``, ``rejoin-required`` (the
vault was joined on another installation), ``already-has-folder``, ``no-group``
(attach to a folder without a keyring) and the keyring reasons of
``attach_with_password`` (``different-group-key``, ``epoch-mismatch``,
``password``, ``tampered``, ``already-member``).  Both re-read the keyring
bytes immediately before writing and abort with ``keyring-changed``.  If the
vault cannot be saved after the keyring was written (it locked meanwhile, or the
save failed), the earlier keyring is put back (none, for a new one) as long as
the folder still holds exactly the bytes written.  If even that fails, a retry
still works: an attach of a device that the keyring already lists with its own
key and a wrap of the stored group key succeeds without rewriting the keyring.
``leave_folder_group`` clears this device's sync state and keeps its own file
in the folder: the file may hold edits the other members have not merged yet
(the leaving device synced, then left before they ran), and deleting it would
lose those edits for the group.  It does NOT rotate (it cannot: rotating needs
a new password, and the leaving device should not hold the new key).  Its
keyring entry and its file stay until a remaining member rotates with
``remove=[that device]``, which deletes the file and stops it reading later
epochs.

Sync is not Pro-gated (licensing revision 2); this module has no licensing
dependency.
"""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import os
import secrets
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from ..updates import canonical_json
from .engine import ItemState, is_valid_id
from .group import (
    MAX_BYTES,
    MAX_SIG_BYTES,
    GroupKey,
    SyncFormatError,
    View,
    decode_view,
    encode_view,
    sign_view,
    verify_view_signature,
)
from .keyring import (
    MAX_KEYRING_BYTES,
    KeyringError,
    WeakSyncPassword,
    accept_keyring,
    attach_with_password,
    create_for_existing_group,
    create_group,
    join_with_password,
    member_names,
    open_with_device_wrap,
    parse_keyring,
    rotate,
)
from .pairing import DeviceIdentity
from .runner import RunReport, SyncIssue, run_merge
from .vault_bridge import (
    _MAX_INT53,
    MAX_INSTALL_ID,
    MAX_MEMBERS_SEEN,
    MAX_PEERS_SEEN,
    TOMBSTONE_MAX_AGE_DAYS,
    SyncGroupState,
    _check_lease,
    clear_sync_state,
    load_sync_state,
    save_sync_state,
)

SYNC_DIR_NAME = "LocalGateKeys Sync"
KEYRING_NAME = "keyring.lgkkeys"
DEVICES_DIR_NAME = "devices"
DEVICE_SUFFIX = ".lgksync"
SIGNATURES_DIR_NAME = "signatures"
SIGNATURE_SUFFIX = ".lgksig"
#: Highest counter accepted from a device's file without a last-seen counter to compare with.
MAX_FILE_COUNTER = 2**40
#: Largest step above the last accepted counter of a device.
MAX_COUNTER_JUMP = 2**24
STALE_AFTER_SECONDS = TOMBSTONE_MAX_AGE_DAYS * 86400
OWN_REFRESH_DAYS = 30
OWN_REFRESH_SECONDS = OWN_REFRESH_DAYS * 86400
MAX_IGNORED_NAMES = 20
KEYRING_TEMP_MAX_AGE = 3600

_RESTORE_KINDS = frozenset({"tampered", "rollback"})
# accept_keyring reasons at trusted epoch + 1 that stop the run without restoring.
_NEXT_EPOCH_STOP_REASONS = frozenset({"tampered", "device-wrap", "key-mismatch"})
_REMOVED_OR_CONFLICT = SyncIssue(
    "removed-or-conflict", "This device may have been removed from sync. Re-join if that isn't expected."
)
_ROTATION_CONFLICT = SyncIssue(
    "rotation-conflict", "another device rotated at the same time; re-join with the newest sync password"
)
_REJOIN_REASONS = frozenset({"missed-rotation", "not-member"})
_TAMPER_REASONS = frozenset({"device-wrap", "key-mismatch"})
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{n}" for n in range(10)} | {f"LPT{n}" for n in range(10)}
)
# Delays before retrying os.replace after a PermissionError (sync clients hold brief locks).
_REPLACE_BACKOFF = (0.05, 0.1, 0.2)


class FolderSyncError(Exception):
    """A folder group operation (create/join/rotate/leave) was refused; ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class PeerRead:
    """Accepted peer views plus issues; ``seen``/``digests`` are the counters and
    sha256 of every file accepted (or recognised as stale) in this read."""

    views: tuple[View, ...] = ()
    issues: tuple[SyncIssue, ...] = ()
    seen: dict[str, int] = field(default_factory=dict)
    digests: dict[str, str] = field(default_factory=dict)
    #: device id -> base64 signing key of every accepted view that carried a valid signature.
    signers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OwnFile:
    """What this device's own file in the folder says (``FolderSync._own_file_status``)."""

    needs_write: bool
    counter: int = 0
    stale: bool = False
    present: bool = False
    #: The file carries a valid signature by this device's own key.
    self_signed: bool = False


def counter_verdict(counter: int, last: int | None) -> str | None:
    """``"rollback"`` or ``"implausible-counter"`` for a peer file's *counter*, None to accept it.

    *last* is the last counter accepted from that device (None: none at this epoch).  Mirrored by
    Kotlin and Swift ``FolderSync.counterVerdict`` (shared cases in ``hardening_cases.json``).
    """
    if last is None:
        return "implausible-counter" if counter > MAX_FILE_COUNTER else None
    if counter < last:
        return "rollback"
    return "implausible-counter" if counter - last > MAX_COUNTER_JUMP else None


def is_safe_device_id(device_id: object) -> bool:
    """A format-1 id that is also a safe Windows/macOS file name stem."""
    if not isinstance(device_id, str) or not is_valid_id(device_id):
        return False
    if ":" in device_id or device_id.startswith(".") or device_id.endswith((".", " ")):
        return False
    return device_id.split(".", 1)[0].upper() not in _RESERVED_NAMES


def _check_install(install_id: object) -> str:
    if (not isinstance(install_id, str) or not install_id or len(install_id) > MAX_INSTALL_ID
            or "\x00" in install_id):
        raise FolderSyncError("bad-install-id", "install id must be a non-empty bounded string")
    return install_id


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* through a temp file in the same directory and ``os.replace``."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with open(tmp, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        for delay in (*_REPLACE_BACKOFF, None):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if delay is None:
                    raise
                time.sleep(delay)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read at most ``limit + 1`` bytes so oversized files fail their decoder's bound."""
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def _member_ids(ring: Mapping[str, Any]) -> set[str]:
    return {m["device_id"] for m in ring["members"]}


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else now


def _ignored_issue(names: list[str]) -> SyncIssue:
    shown = ", ".join(names[:MAX_IGNORED_NAMES])
    more = f", +{len(names) - MAX_IGNORED_NAMES} more" if len(names) > MAX_IGNORED_NAMES else ""
    noun = "file" if len(names) == 1 else "files"
    return SyncIssue("ignored-file", f"{len(names)} {noun}: {shown}{more}")


def _keyring_kind(reason: str) -> str:
    if reason == "group-mismatch":
        return "folder-has-other-group"
    if reason in _RESTORE_KINDS:
        return reason
    if reason in _REJOIN_REASONS:
        return "rejoin-required"
    if reason in _TAMPER_REASONS:
        return "tampered"
    return "keyring-corrupt"


@contextlib.contextmanager
def _helper_errors() -> Iterator[None]:
    """Translate library errors of the group helpers into ``FolderSyncError`` (cause kept)."""
    try:
        yield
    except KeyringError as exc:
        raise FolderSyncError(exc.reason, str(exc)) from exc
    except WeakSyncPassword as exc:
        raise FolderSyncError("weak-password", str(exc)) from exc
    except OSError as exc:
        raise FolderSyncError("folder-error", str(exc)) from exc


class FolderSync:
    """The cloud-folder transport for one vault on one installation.

    *install_id* identifies this installation (the sync service reads it from
    the data directory); a vault whose stored install id differs refuses to
    sync.
    """

    def __init__(self, root: Path | str, *, install_id: str,
                 _kdf_override: tuple[int, int, int] | None = None) -> None:
        self.root = Path(root)
        self.install_id = _check_install(install_id)
        self._kdf_override = _kdf_override

    @property
    def sync_dir(self) -> Path:
        return self.root / SYNC_DIR_NAME

    @property
    def keyring_path(self) -> Path:
        return self.sync_dir / KEYRING_NAME

    @property
    def devices_dir(self) -> Path:
        return self.sync_dir / DEVICES_DIR_NAME

    @property
    def signatures_dir(self) -> Path:
        return self.sync_dir / SIGNATURES_DIR_NAME

    def signature_file(self, device_id: str) -> Path:
        """Path of *device_id*'s view signature; ValueError unless the id is a safe file name."""
        if not is_safe_device_id(device_id):
            raise ValueError("device id is not a safe file name")
        name = f"{device_id}{SIGNATURE_SUFFIX}"
        path = self.signatures_dir / name
        if path.parent != self.signatures_dir or path.name != name:
            raise ValueError("signature file escapes the signatures folder")
        return path

    def _read_signature(self, device_id: str) -> bytes | None:
        """The raw signature file of *device_id*, None when missing or unreadable."""
        try:
            path = self.signature_file(device_id)
            if path.is_symlink():
                return None
            return _read_bounded(path, MAX_SIG_BYTES)
        except (OSError, ValueError):
            return None

    def device_file(self, device_id: str) -> Path:
        """Path of *device_id*'s file; ValueError unless the id is a safe file name."""
        if not is_safe_device_id(device_id):
            raise ValueError("device id is not a safe file name")
        name = f"{device_id}{DEVICE_SUFFIX}"
        path = self.devices_dir / name
        if path.parent != self.devices_dir or path.name != name:
            raise ValueError("device file escapes the devices folder")
        return path

    # --- keyring -----------------------------------------------------------------------

    def read_keyring_bytes(self) -> bytes:
        """Raw keyring bytes (bounded); raises FileNotFoundError or OSError."""
        return _read_bounded(self.keyring_path, MAX_KEYRING_BYTES)

    def read_keyring(self) -> dict:
        """Parsed keyring; raises FileNotFoundError, OSError or KeyringError."""
        return parse_keyring(self.read_keyring_bytes())

    def write_keyring(self, ring: Mapping[str, Any], *, expected: bytes | None) -> bytes:
        """Atomically write *ring* if the folder still holds *expected* (None: no keyring).

        Raises ``FolderSyncError("keyring-changed")`` otherwise; returns the bytes written.
        """
        data = canonical_json(dict(ring))
        self.sync_dir.mkdir(exist_ok=True)
        try:
            current: bytes | None = self.read_keyring_bytes()
        except FileNotFoundError:
            current = None
        if current != expected:
            raise FolderSyncError("keyring-changed", "another device changed the keyring; try again")
        _atomic_write(self.keyring_path, data)
        return data

    def _restore_keyring(self, state: SyncGroupState, trusted: GroupKey) -> tuple[GroupKey, dict] | None:
        """Re-verify the stored keyring and write it back; None if that is impossible."""
        if state.keyring is None:
            return None
        try:
            ring = parse_keyring(state.keyring)
            gk = accept_keyring(ring, trusted, state.identity(), _kdf_override=self._kdf_override)
        except KeyringError:
            return None
        if gk.epoch != trusted.epoch:
            return None
        try:
            self.sync_dir.mkdir(exist_ok=True)
            _atomic_write(self.keyring_path, state.keyring)
        except OSError:
            return None
        return gk, ring

    def _trusted_keyring(
        self, state: SyncGroupState
    ) -> tuple[list[SyncIssue], GroupKey | None, dict | None, bytes | None]:
        """(issues, key, ring, ring bytes); key None means the run must stop."""
        try:
            raw = self.read_keyring_bytes()
        except FileNotFoundError:
            return [SyncIssue("keyring-missing", KEYRING_NAME)], None, None, None
        except OSError as exc:
            return [SyncIssue("keyring-unreadable", str(exc))], None, None, None
        trusted = GroupKey(state.group_id, state.epoch, state.key)
        try:
            ring = parse_keyring(raw)
        except KeyringError as exc:
            return [SyncIssue("keyring-corrupt", str(exc))], None, None, None
        try:
            gk = accept_keyring(ring, trusted, state.identity(), _kdf_override=self._kdf_override)
        except KeyringError as exc:
            kind = _keyring_kind(exc.reason)
            detail = str(exc) if exc.reason == kind else f"{kind}: {exc}"
            same_group = ring.get("group_id") == trusted.group_id
            epoch = ring.get("epoch")
            if same_group and epoch == trusted.epoch + 1 and exc.reason in _NEXT_EPOCH_STOP_REASONS:
                # A rotation that does not chain from our key (e.g. the winner of an
                # earlier rotation conflict rotated again): never restore over it.
                if self._unlisted(ring, state):
                    return [_REMOVED_OR_CONFLICT], None, None, None
                return [_ROTATION_CONFLICT], None, None, None
            if same_group and epoch == trusted.epoch and exc.reason == "tampered" and self._unlisted(ring, state):
                return [_REMOVED_OR_CONFLICT], None, None, None
            if exc.reason == "tampered" and self._competing_rotation(ring, trusted, state):
                return [_ROTATION_CONFLICT], None, None, None
            if kind in _RESTORE_KINDS and not (isinstance(epoch, int) and epoch > trusted.epoch):
                restored = self._restore_keyring(state, trusted)
                if restored is not None:
                    return [SyncIssue("keyring-restored", detail)], restored[0], restored[1], state.keyring
            return [SyncIssue(kind, detail)], None, None, None
        return [], gk, ring, raw

    @staticmethod
    def _unlisted(ring: Mapping[str, Any], state: SyncGroupState) -> bool:
        """True if *ring* does not list this device or lacks its wrap.

        A rotation that removed this device and overlapped another rotation looks
        exactly like this; restoring the stored keyring would undo the removal.
        """
        members = ring.get("members")
        wraps = ring.get("device_wraps")
        listed = isinstance(members, list) and any(
            isinstance(m, Mapping) and m.get("device_id") == state.device_id for m in members
        )
        wrapped = isinstance(wraps, Mapping) and state.device_id in wraps
        return not (listed and wrapped)

    def _competing_rotation(self, ring: Mapping[str, Any], trusted: GroupKey, state: SyncGroupState) -> bool:
        """True if *ring* is at the trusted epoch, opens with our own wrap and verifies under that key.

        Two members rotating from the same epoch each write a valid keyring with
        a different key; restoring would make them overwrite each other forever.
        """
        if ring.get("group_id") != trusted.group_id or ring.get("epoch") != trusted.epoch:
            return False
        try:
            other = open_with_device_wrap(dict(ring), state.identity(), _kdf_override=self._kdf_override)
        except KeyringError:
            return False
        return other.key != trusted.key

    # --- device files ------------------------------------------------------------------

    def read_peers(self, gk: GroupKey, own_id: str, members: Iterable[str], last_seen: Mapping[str, int],
                   digests: Mapping[str, str], *, now: int, signers: Mapping[str, str] | None = None,
                   paired_keys: Mapping[str, str] | None = None) -> PeerRead:
        """Read every peer file; never raises for a single bad file (see module docstring).

        *signers*: pinned signing keys (base64) of devices whose views must be signed;
        *paired_keys*: the only key a device's signature may carry (LAN pairing), signed or not.
        """
        signers = signers or {}
        paired_keys = paired_keys or {}
        issues: list[SyncIssue] = []
        allowed: set[str] = set()
        for member in sorted(set(members) - {own_id}):
            if is_safe_device_id(member):
                allowed.add(member)
            else:
                issues.append(SyncIssue("unsafe-member", member))
        ignored: list[str] = []
        views: list[View] = []
        seen: dict[str, int] = {}
        digs: dict[str, str] = {}
        signed: dict[str, str] = {}
        try:
            names = sorted(entry.name for entry in os.scandir(self.devices_dir))
        except FileNotFoundError:
            return PeerRead(issues=tuple(issues))
        except OSError as exc:
            return PeerRead(issues=(*issues, SyncIssue("folder-unreadable", str(exc))))
        for name in names:
            if name.startswith(".") and name.endswith(".tmp"):
                continue  # an in-flight atomic write
            dev = name[: -len(DEVICE_SUFFIX)] if name.endswith(DEVICE_SUFFIX) else ""
            if dev == own_id:
                continue
            if dev not in allowed:
                ignored.append(name)
                continue
            path = self.device_file(dev)
            if path.is_symlink() or not path.is_file():
                ignored.append(name)
                continue
            try:
                raw = _read_bounded(path, MAX_BYTES)
            except OSError as exc:
                issues.append(SyncIssue("unreadable", f"{name}: {exc}"))
                continue
            try:
                view = decode_view(gk, raw, expected_device_id=dev)
            except SyncFormatError as exc:
                kind = exc.reason if exc.reason in ("epoch-mismatch", "device-mismatch") else "corrupt"
                issues.append(SyncIssue(kind, f"{name}: {exc.reason}"))
                continue
            counter = view.header["counter"]
            digest = hashlib.sha256(raw).hexdigest()
            last = last_seen.get(dev)
            if last is not None and counter < last:
                issues.append(SyncIssue("rollback", f"{name}: counter {counter} < {last}"))
                continue
            if last == counter and digests.get(dev, digest) != digest:
                issues.append(SyncIssue("suspicious-rewrite", f"{name}: counter {counter} reused"))
                continue
            signer = self._check_signature(dev, name, raw, view, signers, paired_keys, issues)
            if signer is False:
                continue
            if counter_verdict(counter, last) is not None:
                issues.append(SyncIssue("implausible-counter", f"{name}: counter {counter}"))
                continue
            seen[dev], digs[dev] = counter, digest
            if isinstance(signer, str):
                signed[dev] = signer
            if view.header["written_at"] < now - STALE_AFTER_SECONDS:
                issues.append(SyncIssue("stale-device", name))
                continue
            views.append(view)
        if ignored:
            issues.append(_ignored_issue(ignored))
        return PeerRead(tuple(views), tuple(issues), seen, digs, signed)

    def _check_signature(self, dev: str, name: str, raw: bytes, view: View, signers: Mapping[str, str],
                         paired_keys: Mapping[str, str], issues: list[SyncIssue]) -> str | bool | None:
        """The signing key (base64) of a validly signed view, None for an accepted unsigned one, False to skip."""
        expected = paired_keys.get(dev) or signers.get(dev)
        sig = self._read_signature(dev)
        why = "no signature file"
        if sig is not None:
            try:
                public = base64.b64encode(verify_view_signature(sig, raw, view.header)).decode("ascii")
            except SyncFormatError as exc:
                why = exc.reason
            else:
                if expected is not None and public != expected:
                    issues.append(SyncIssue("view-forged", f"{name}: signed by another key"))
                    return False
                return public
        if dev not in signers:
            return None  # a device that never signed (older app): accepted as before
        kind = "view-forged" if why == "sig-mismatch" else "view-unsigned"
        issues.append(SyncIssue(kind, f"{name}: {why}"))
        return False

    def write_own(self, gk: GroupKey, device_id: str, states: Iterable[ItemState], counter: int, *,
                  now: int, signing_key: ed25519.Ed25519PrivateKey | None = None) -> None:
        """Encode and atomically write this device's own file, then its signature (if *signing_key*)."""
        path = self.device_file(device_id)
        raw = encode_view(gk, device_id, counter, states, now)
        sig = sign_view(raw, signing_key) if signing_key is not None else None
        self.devices_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, raw)
        if sig is not None:
            self.signatures_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.signature_file(device_id), sig)

    def _sweep_own_temp_files(self, device_id: str) -> None:
        """Delete this device's leftover temp files (an earlier crash between write and replace)."""
        prefix = f".{device_id}{DEVICE_SUFFIX}."
        try:
            names = [e.name for e in os.scandir(self.devices_dir)]
        except OSError:
            return
        for name in names:
            if name.startswith(prefix) and name.endswith(".tmp"):
                with contextlib.suppress(OSError):
                    (self.devices_dir / name).unlink()

    def _sweep_keyring_temp_files(self, now: int) -> None:
        """Delete keyring temp files older than an hour (a writer that crashed, on any device)."""
        prefix = f".{KEYRING_NAME}."
        try:
            entries = [e for e in os.scandir(self.sync_dir) if e.name.startswith(prefix) and e.name.endswith(".tmp")]
        except OSError:
            return
        for entry in entries:
            with contextlib.suppress(OSError):
                if entry.stat(follow_symlinks=False).st_mtime < now - KEYRING_TEMP_MAX_AGE:
                    os.unlink(entry.path)

    def _folder_exists(self) -> bool:
        return self.sync_dir.is_dir()

    def _own_file_status(self, gk: GroupKey, state: SyncGroupState, own_states: tuple[ItemState, ...] | None,
                         now: int) -> OwnFile:
        """What the own file holds; a file without a valid own signature always needs a write."""
        try:
            raw = _read_bounded(self.device_file(state.device_id), MAX_BYTES)
            view = decode_view(gk, raw, expected_device_id=state.device_id)
        except (OSError, ValueError):  # SyncFormatError is a ValueError
            return OwnFile(own_states is not None)
        counter, written_at = view.header["counter"], view.header["written_at"]
        stale = written_at < now - STALE_AFTER_SECONDS
        self_signed = False
        sig = self._read_signature(state.device_id)
        if sig is not None:
            try:
                self_signed = verify_view_signature(sig, raw, view.header) == state.identity().signing_public_key
            except SyncFormatError:
                self_signed = False
        if own_states is None:
            return OwnFile(False, counter, stale, True, self_signed)
        needs = (view.states != own_states or counter != state.own_counter or not self_signed
                 or written_at < now - OWN_REFRESH_SECONDS)
        return OwnFile(needs, counter, stale, True, self_signed)

    # --- one run -----------------------------------------------------------------------

    def run_once(self, session: Any, lease: Any, *, now: int) -> RunReport:
        """One full folder sync; see the module docstring."""
        _check_lease(session, lease)
        state = load_sync_state(session)
        if state is None:
            return RunReport(issues=(SyncIssue("not-joined"),))
        if state.install_id != self.install_id:
            return RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
        if not self._folder_exists():
            return RunReport(issues=(SyncIssue("folder-missing", str(self.sync_dir)),))

        issues, gk, ring, ring_bytes = self._trusted_keyring(state)
        if gk is None or ring is None or ring_bytes is None:
            return RunReport(issues=tuple(issues) or (SyncIssue("keyring-corrupt"),))

        current = _member_ids(ring)
        unacked = _unacked_members(state, current)
        if gk.epoch != state.epoch:
            # Members a rotation removed are dropped from the LAN peer list as well.  The key
            # changed, so a Wi-Fi peer removed earlier no longer holds it (lan_removed).
            removed = set(state.members) - current
            state = dataclasses.replace(state, epoch=gk.epoch, key=gk.key, members_epoch=gk.epoch,
                                        members=tuple(sorted(current)), keyring=ring_bytes,
                                        lan_peers=tuple(p for p in state.lan_peers
                                                        if p.get("device_id") not in removed),
                                        lan_removed=False, unacked_members=unacked,
                                        **_epoch_reset(state))
            _check_lease(session, lease)
            save_sync_state(session, state)
        known = set(state.members) if state.members_epoch == gk.epoch else set()
        for dropped in sorted(known - current):
            issues.append(SyncIssue("member-dropped", dropped))
        if state.device_id not in current and state.device_id not in known:
            issues.append(SyncIssue("member-dropped", state.device_id))
        for added in unacked:
            issues.append(SyncIssue("member-added", added))
        if state.lan_removed:
            issues.append(SyncIssue("old-key-known", "a removed Wi-Fi device still holds the current key"))
        for device_id, name in member_names(ring, gk).items():  # ring is accepted under gk
            if name is None:
                issues.append(SyncIssue("bad-name", device_id))
        members = known | current
        if len(members) > MAX_MEMBERS_SEEN:
            members = current

        if is_safe_device_id(state.device_id):
            self._sweep_own_temp_files(state.device_id)
        self._sweep_keyring_temp_files(now)
        peers = self.read_peers(gk, state.device_id, members, state.last_seen, state.peer_digests, now=now,
                                signers={d: k for d, k in state.view_signers.items() if d != state.device_id},
                                paired_keys=_paired_keys(state))
        issues.extend(peers.issues)
        report = run_merge(session, lease, device_id=state.device_id, views=peers.views, now=now)
        issues.extend(report.issues)

        identity = state.identity()
        own_key = base64.b64encode(identity.signing_public_key).decode("ascii")
        last_seen = {**state.last_seen, **peers.seen}
        digests = {**state.peer_digests, **peers.digests}
        signers = {**state.view_signers, **peers.signers}
        if len(last_seen) > MAX_PEERS_SEEN or len(digests) > MAX_PEERS_SEEN or len(signers) > MAX_PEERS_SEEN:
            last_seen = {d: c for d, c in last_seen.items() if d in members}
            digests = {d: h for d, h in digests.items() if d in members}
            signers = {d: k for d, k in signers.items() if d in members}
        new_state = dataclasses.replace(state, last_seen=last_seen, peer_digests=digests,
                                        members_epoch=gk.epoch, members=tuple(sorted(members)),
                                        keyring=ring_bytes, unacked_members=unacked, view_signers=signers)
        own = self._own_file_status(gk, state, report.own_states, now)
        needs_write, file_counter = own.needs_write, own.counter
        if own.stale:
            issues.append(SyncIssue("stale-self", "this device had not synced for over a year"))
        signed_before = state.view_signers.get(state.device_id) == own_key
        if own.present and not own.self_signed and (
                file_counter > state.own_counter or (signed_before and file_counter == state.own_counter)):
            # Not written by this device: someone holding the group key wrote our file.
            issues.append(SyncIssue("own-file-rewritten", f"{state.device_id}{DEVICE_SUFFIX}: counter "
                                                          f"{file_counter}, reserved {state.own_counter}"))
            if file_counter - state.own_counter > MAX_COUNTER_JUMP:
                file_counter = state.own_counter  # peers refused it as implausible: do not follow it
        elif file_counter > state.own_counter:
            # The vault is older than this device's own file (restored from a
            # backup): continue above the file's counter instead of reusing one.
            issues.append(SyncIssue("counter-resynced", f"own file counter {file_counter} > reserved "
                                                        f"{state.own_counter}"))
        counter = max(state.own_counter, file_counter) + 1
        if counter > _MAX_INT53:
            # Only a counter stored before the bounds existed can get here; never fail the whole run.
            issues.append(SyncIssue("counter-exhausted", f"own counter {counter - 1}"))
            needs_write = False
        if needs_write:
            new_state = dataclasses.replace(new_state, own_counter=counter,
                                            view_signers={**new_state.view_signers, state.device_id: own_key})
        if new_state != state:
            _check_lease(session, lease)
            save_sync_state(session, new_state)  # reserve the counter before writing

        wrote = False
        if needs_write and report.own_states is not None:
            _check_lease(session, lease)
            try:
                self.write_own(gk, state.device_id, report.own_states, counter, now=now,
                               signing_key=identity.signing_key)
                wrote = True
            except SyncFormatError as exc:
                issues.append(SyncIssue("too-large", str(exc)))
            except (OSError, ValueError) as exc:
                issues.append(SyncIssue("write-failed", str(exc)))
        return dataclasses.replace(report, issues=tuple(issues), wrote=wrote)


def _epoch_reset(state: SyncGroupState) -> dict[str, Any]:
    """Fields cleared when this device moves to a new epoch: per-peer counters, digests and signing keys.

    Only members of the new epoch can write files for it, so a counter or key forged by a
    member that the rotation removed no longer blocks anyone.  This device's own key stays.
    """
    own = {d: k for d, k in state.view_signers.items() if d == state.device_id}
    return {"last_seen": {}, "peer_digests": {}, "view_signers": own}


def _paired_keys(state: SyncGroupState) -> dict[str, str]:
    """device id -> base64 signing key of every LAN-paired peer (authenticated by its QR pairing)."""
    out: dict[str, str] = {}
    for peer in state.lan_peers:
        dev, key = peer.get("device_id"), peer.get("signing_public")
        if isinstance(dev, str) and isinstance(key, str) and dev != state.device_id:
            out[dev] = key
    return out


def _unacked_members(state: SyncGroupState, current: set[str]) -> tuple[str, ...]:
    """Members to report as ``member-added``: unacknowledged ones still listed, plus new arrivals.

    A new arrival is a member of *current* (the accepted keyring) that this device did not
    know at its last run (``state.members``) and that is not this device.  This device never
    adds another member itself (joiners add themselves; its own rotation acknowledges every
    member it keeps), so every arrival was added elsewhere.  A legacy state without a
    recorded member list reports nothing.  At most ``MAX_MEMBERS_SEEN`` ids are kept.
    """
    unacked = set(state.unacked_members) & current
    if state.members_epoch is not None:
        unacked |= current - set(state.members) - {state.device_id}
    return tuple(sorted(unacked)[:MAX_MEMBERS_SEEN])


# --- group operations for the UI ------------------------------------------------------------


def _healthy_member(ring: dict, state: SyncGroupState, kdf: tuple[int, int, int] | None) -> bool:
    """True if this device already trusts *ring* (same epoch or the next) and is a member of it."""
    trusted = GroupKey(state.group_id, state.epoch, state.key)
    try:
        accept_keyring(ring, trusted, state.identity(), _kdf_override=kdf)
    except KeyringError:
        return False
    return state.device_id in _member_ids(ring)


UiRelease = Callable[[], AbstractContextManager[None]]


def create_folder_group(root: Path | str, session: Any, lease: Any, password: str, device_name: str, *,
                        install_id: str, now: int | None = None, ui_released: UiRelease | None = None,
                        run: bool = True, _kdf_override: tuple[int, int, int] | None = None) -> RunReport:
    """Start a new group in *root* with this vault as its first member, then run once.

    *ui_released* (``SyncGate.ui_released`` in the app) wraps the Argon2id
    derivation and every folder access, so the UI is not parked during them;
    vault reads and writes stay outside it.  ``run=False`` skips the first run
    (the app asks the sync service for one instead) and returns an empty report.
    """
    free = ui_released or contextlib.nullcontext
    fs = FolderSync(root, install_id=install_id, _kdf_override=_kdf_override)
    _check_lease(session, lease)
    with _helper_errors():
        if load_sync_state(session) is not None:
            raise FolderSyncError("already-joined", "leave the current sync group first")
        with free():
            if not fs.root.is_dir():
                raise FolderSyncError("folder-missing", str(fs.root))
            if fs.keyring_path.exists():
                raise FolderSyncError("folder-in-use", "this folder already holds a sync group; join it instead")
            identity = DeviceIdentity.generate()
            ring, gk = create_group(password, identity, device_name, _kdf_override=_kdf_override)
            fs.devices_dir.mkdir(parents=True, exist_ok=True)
            written = fs.write_keyring(ring, expected=None)
        state = SyncGroupState(gk.group_id, gk.epoch, gk.key, identity.protected_dict(),
                               folder_path=str(fs.root), install_id=install_id,
                               members_epoch=gk.epoch, members=(identity.device_id,), keyring=written)
        try:
            _check_lease(session, lease)
            save_sync_state(session, state)
        except BaseException:
            with free(), contextlib.suppress(OSError):
                fs.keyring_path.unlink()
            raise
    if not run:
        return RunReport()
    return fs.run_once(session, lease, now=_now(now))


def join_folder_group(root: Path | str, session: Any, lease: Any, password: str, device_name: str, *,
                      install_id: str, now: int | None = None, ui_released: UiRelease | None = None,
                      run: bool = True, _kdf_override: tuple[int, int, int] | None = None) -> RunReport:
    """Join the group in *root* with the sync password (fresh device identity), then run once.

    Refuses a folder of another group than the one this vault is in
    (``different-group``) and a healthy membership of the same group
    (``already-joined``: the folder keyring is one this device accepts and lists
    it).  Re-joining the same group (missed rotations, removed, a rotation
    conflict, or vault moved to another installation) is allowed.  Aborts with
    ``keyring-changed`` if the keyring changed while the password was checked.
    *ui_released* and *run* as for ``create_folder_group``.
    """
    free = ui_released or contextlib.nullcontext
    fs = FolderSync(root, install_id=install_id, _kdf_override=_kdf_override)
    _check_lease(session, lease)
    with _helper_errors():
        with free():
            try:
                raw = fs.read_keyring_bytes()
            except FileNotFoundError:
                raise FolderSyncError("no-group", "no sync group in this folder") from None
            ring = parse_keyring(raw)
        state = load_sync_state(session)
        with free():
            if state is not None:
                if state.group_id != ring.get("group_id"):
                    raise FolderSyncError("different-group", "this vault already syncs with another group")
                if state.install_id == install_id and _healthy_member(ring, state, _kdf_override):
                    raise FolderSyncError("already-joined", "this vault is already a member")
            identity = DeviceIdentity.generate()
            new_ring, gk = join_with_password(ring, password, identity, device_name, _kdf_override=_kdf_override)
            written = fs.write_keyring(new_ring, expected=raw)
        same = state is not None
        # Counters seen at another epoch are dropped (see ``_epoch_reset``); the new identity signs afresh.
        same_epoch = same and state.epoch == gk.epoch
        new_state = SyncGroupState(
            gk.group_id, gk.epoch, gk.key, identity.protected_dict(),
            last_seen=state.last_seen if same_epoch else {},
            peer_digests=state.peer_digests if same_epoch else {},
            folder_path=str(fs.root),
            lan_peers=state.lan_peers if same else (),
            install_id=install_id,
            members_epoch=gk.epoch,
            members=tuple(sorted(_member_ids(new_ring))),
            keyring=written,
            # The same key (a re-join at the epoch this vault already had) is still known to a
            # removed Wi-Fi peer; a newer key is not.
            lan_removed=bool(same and state.lan_removed and gk.key == state.key),
        )
        _check_lease(session, lease)
        save_sync_state(session, new_state)
        if same and state.install_id == install_id:
            # Our previous identity's file on this installation is obsolete.
            with free(), contextlib.suppress(OSError, ValueError):
                fs.device_file(state.device_id).unlink()
            with free(), contextlib.suppress(OSError, ValueError):
                fs.signature_file(state.device_id).unlink()
    if not run:
        return RunReport()
    return fs.run_once(session, lease, now=_now(now))


def rotate_folder_group(root: Path | str, session: Any, lease: Any, new_password: str,
                        remove: Iterable[str] = (), *, keep: Iterable[str] | None = None, install_id: str,
                        now: int | None = None, ui_released: UiRelease | None = None, run: bool = True,
                        _kdf_override: tuple[int, int, int] | None = None) -> RunReport:
    """New group key and sync password (epoch + 1), dropping *remove*; deletes their files.

    The new key is wrapped only to this device and to the members in *keep*: the
    members the user saw and confirmed (audit M10).  Every other member of the
    keyring (one added after the user looked, e.g. a sock puppet that a device
    about to be removed added at the same epoch) is dropped like *remove*.
    *keep* None means the members this device knows and that are acknowledged
    (``SyncGroupState.members`` without ``unacked_members``).  After the
    rotation no member is unacknowledged and ``lan_removed`` is cleared.

    Members whose ids are not safe file names are removed from the keyring but
    nothing is unlinked for them.  Aborts with ``keyring-changed`` if the
    keyring changed during the rotation.  *ui_released* and *run* as for
    ``create_folder_group``.
    """
    free = ui_released or contextlib.nullcontext
    fs = FolderSync(root, install_id=install_id, _kdf_override=_kdf_override)
    _check_lease(session, lease)
    with _helper_errors():
        state = load_sync_state(session)
        if state is None:
            raise FolderSyncError("not-joined")
        if state.install_id != install_id:
            raise FolderSyncError("rejoin-required", "this vault was joined on another installation")
        drop = list(remove)
        if not all(is_valid_id(d) for d in drop):
            raise FolderSyncError("not-member", "invalid device id")
        if keep is None:
            known = set(state.members) if state.members_epoch == state.epoch else set()
            kept = known - set(state.unacked_members)
        else:
            kept = set(keep)
            if not all(isinstance(k, str) and is_valid_id(k) for k in kept):
                raise FolderSyncError("not-member", "invalid device id")
        identity = state.identity()
        with free():
            raw = fs.read_keyring_bytes()
            ring = parse_keyring(raw)
            lan_ids = {p.get("device_id") for p in state.lan_peers}
            # A LAN-only peer (never in the keyring) is removed from the LAN list only.
            ring_drop = [d for d in drop if d in _member_ids(ring) or d not in lan_ids]
            # Members nobody confirmed never receive the new key.
            unconfirmed = sorted(_member_ids(ring) - kept - set(drop) - {state.device_id})
            ring_drop += unconfirmed
            drop += unconfirmed
            trusted = GroupKey(state.group_id, state.epoch, state.key)
            new_ring, gk = rotate(ring, trusted, identity, new_password, remove=ring_drop,
                                  _kdf_override=_kdf_override)
            written = fs.write_keyring(new_ring, expected=raw)
        gone = set(drop)
        new_state = dataclasses.replace(
            state, epoch=gk.epoch, key=gk.key, members_epoch=gk.epoch,
            members=tuple(sorted(_member_ids(new_ring))),
            lan_peers=tuple(p for p in state.lan_peers if p.get("device_id") not in gone),
            keyring=written, lan_removed=False, unacked_members=(), **_epoch_reset(state),
        )
        _check_lease(session, lease)
        save_sync_state(session, new_state)
        with free():
            for dev in sorted(gone):
                if not is_safe_device_id(dev):
                    continue
                with contextlib.suppress(FileNotFoundError):
                    fs.device_file(dev).unlink()
                with contextlib.suppress(FileNotFoundError):
                    fs.signature_file(dev).unlink()
    if not run:
        return RunReport()
    return fs.run_once(session, lease, now=_now(now))


def _wifi_group_state(session: Any, lease: Any, install_id: str) -> SyncGroupState:
    """The stored group of a vault that may get a folder: joined here, without a folder yet."""
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        raise FolderSyncError("not-joined")
    if state.install_id != install_id:
        raise FolderSyncError("rejoin-required", "this vault was joined on another installation")
    if state.folder_path is not None:
        raise FolderSyncError("already-has-folder", "this sync group already uses a cloud folder")
    return state


def _read_folder_keyring(fs: FolderSync, state: SyncGroupState) -> tuple[bytes, dict] | None:
    """(bytes, parsed) of the folder's keyring, None without one; another group's is refused."""
    try:
        raw = fs.read_keyring_bytes()
    except FileNotFoundError:
        return None
    ring = parse_keyring(raw)
    if ring.get("group_id") != state.group_id:
        raise FolderSyncError("folder-has-other-group", "this folder holds another sync group")
    return raw, ring


def _attach(fs: FolderSync, session: Any, lease: Any, state: SyncGroupState, raw: bytes, ring: dict,
            password: str, device_name: str, free: UiRelease, kdf: tuple[int, int, int] | None) -> None:
    """Add this device (with its own identity) to the folder keyring of its group; store the folder."""
    with free():
        stored = GroupKey(state.group_id, state.epoch, state.key)
        new_ring = attach_with_password(ring, password, state.identity(), device_name, stored, _kdf_override=kdf)
        # Unchanged: an earlier attach of this device wrote the keyring but did not finish.
        written = raw if new_ring is ring else fs.write_keyring(new_ring, expected=raw)
    new_state = dataclasses.replace(state, folder_path=str(fs.root), members_epoch=state.epoch,
                                    members=tuple(sorted(_member_ids(new_ring))), keyring=written)
    try:
        _check_lease(session, lease)
        save_sync_state(session, new_state)
    except BaseException:
        if written != raw:
            with free():
                _undo_keyring_write(fs, written, raw)
        raise


def _undo_keyring_write(fs: FolderSync, written: bytes, previous: bytes | None) -> None:
    """Best effort: put *previous* back (None: remove) if the folder still holds exactly *written*."""
    with contextlib.suppress(OSError):
        if fs.read_keyring_bytes() != written:
            return  # another device wrote since; leave its keyring alone
        if previous is None:
            fs.keyring_path.unlink()
        else:
            _atomic_write(fs.keyring_path, previous)


def add_folder_to_group(root: Path | str, session: Any, lease: Any, password: str, device_name: str, *,
                        install_id: str, now: int | None = None, ui_released: UiRelease | None = None,
                        run: bool = True, fresh_key: bool = False,
                        _kdf_override: tuple[int, int, int] | None = None) -> RunReport:
    """Give this vault's Wi-Fi-only group a cloud folder in *root* with a new sync password, then run once.

    The keyring is built for the stored group key (``create_for_existing_group``), so
    the paired devices stay in the group and join the folder with ``attach_folder``.
    A folder that already holds this group is attached to with *password* instead.
    *ui_released* and *run* as for ``create_folder_group``.

    Audit M9: if a Wi-Fi peer was removed since the key last changed
    (``SyncGroupState.lan_removed``), that peer still holds the stored key, so a
    new folder must not be protected by it.  Without *fresh_key* the call is then
    refused with ``lan-peer-removed`` and nothing is written.  With *fresh_key*
    (the user confirmed) the keyring is made for a NEW random key at the stored
    epoch + 1 (same group id, ``prev_mac`` null like any first keyring) and this
    device moves to it.  LAN never delivers keys, so the remaining Wi-Fi peers
    stay at the old epoch: they keep their pairing entry, are answered
    ``epoch-behind`` ("pair it again") and exchange nothing with this device until
    they pair again by QR (or join the folder with its sync password).
    """
    free = ui_released or contextlib.nullcontext
    fs = FolderSync(root, install_id=install_id, _kdf_override=_kdf_override)
    with _helper_errors():
        state = _wifi_group_state(session, lease, install_id)
        with free():
            if not fs.root.is_dir():
                raise FolderSyncError("folder-missing", str(fs.root))
            existing = _read_folder_keyring(fs, state)
        if existing is not None:
            _attach(fs, session, lease, state, *existing, password, device_name, free, _kdf_override)
        else:
            if state.lan_removed and not fresh_key:
                raise FolderSyncError("lan-peer-removed", "a removed Wi-Fi device still holds this group's key")
            identity = state.identity()
            gk = GroupKey(state.group_id, state.epoch, state.key)
            if fresh_key:
                gk = GroupKey(state.group_id, state.epoch + 1, secrets.token_bytes(32))
            with free():
                ring = create_for_existing_group(gk, password, identity, device_name, _kdf_override=_kdf_override)
                fs.devices_dir.mkdir(parents=True, exist_ok=True)
                written = fs.write_keyring(ring, expected=None)
            reset = _epoch_reset(state) if gk.epoch != state.epoch else {}
            new_state = dataclasses.replace(state, epoch=gk.epoch, key=gk.key, folder_path=str(fs.root),
                                            members_epoch=gk.epoch, members=(identity.device_id,), keyring=written,
                                            lan_removed=False, unacked_members=(), **reset)
            try:
                _check_lease(session, lease)
                save_sync_state(session, new_state)
            except BaseException:
                with free():
                    _undo_keyring_write(fs, written, None)
                raise
    if not run:
        return RunReport()
    return fs.run_once(session, lease, now=_now(now))


def attach_folder(root: Path | str, session: Any, lease: Any, password: str, device_name: str, *,
                  install_id: str, now: int | None = None, ui_released: UiRelease | None = None,
                  run: bool = True, _kdf_override: tuple[int, int, int] | None = None) -> RunReport:
    """Use the cloud folder another device added to this vault's Wi-Fi-only group, then run once.

    This device keeps its identity and LAN peers; the sync password must open exactly
    the stored group key (``attach_with_password``).  *ui_released* and *run* as for
    ``create_folder_group``.
    """
    free = ui_released or contextlib.nullcontext
    fs = FolderSync(root, install_id=install_id, _kdf_override=_kdf_override)
    with _helper_errors():
        state = _wifi_group_state(session, lease, install_id)
        with free():
            existing = _read_folder_keyring(fs, state)
        if existing is None:
            raise FolderSyncError("no-group", "no sync group in this folder")
        _attach(fs, session, lease, state, *existing, password, device_name, free, _kdf_override)
    if not run:
        return RunReport()
    return fs.run_once(session, lease, now=_now(now))


def acknowledge_members(session: Any, lease: Any, device_ids: Iterable[str], *, install_id: str) -> int:
    """The user confirmed *device_ids* (reported as ``member-added``); stop reporting them.

    Only the ids passed are acknowledged, so a member that appeared after the user
    looked stays reported.  Returns how many were acknowledged.
    """
    _check_install(install_id)
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        raise FolderSyncError("not-joined")
    if state.install_id != install_id:
        raise FolderSyncError("rejoin-required", "this vault was joined on another installation")
    chosen = {d for d in device_ids if isinstance(d, str)}
    left = tuple(d for d in state.unacked_members if d not in chosen)
    if len(left) == len(state.unacked_members):
        return 0
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, unacked_members=left))
    return len(state.unacked_members) - len(left)


def leave_folder_group(session: Any, lease: Any, *, install_id: str) -> bool:
    """Clear this vault's sync state; this device's own file stays in the folder.

    Local items stay.  Returns whether there was a state to clear.  The own
    file is NOT deleted: the other members may not have merged its last edits
    yet, and they still read it until one of them rotates with
    ``remove=[this device]``, which deletes it.  Does not rotate (see the
    module docstring).
    """
    _check_install(install_id)
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None:
        return False
    _check_lease(session, lease)
    clear_sync_state(session)
    return True


__all__ = [
    "DEVICE_SUFFIX", "KEYRING_NAME", "MAX_COUNTER_JUMP", "MAX_FILE_COUNTER", "OWN_REFRESH_DAYS", "SIGNATURE_SUFFIX",
    "SIGNATURES_DIR_NAME", "SYNC_DIR_NAME", "FolderSync", "FolderSyncError", "counter_verdict",
    "PeerRead", "RunReport", "SyncIssue", "acknowledge_members", "add_folder_to_group", "attach_folder", "create_folder_group", "is_safe_device_id", "join_folder_group",
    "leave_folder_group", "rotate_folder_group",
]
