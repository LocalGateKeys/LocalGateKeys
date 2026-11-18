"""Cloud-folder sync transport: encrypted device files in a user-chosen folder.

Layout (inside the folder the user picks: OneDrive, Dropbox, iCloud Drive...)::

    <root>/LocalGateKeys Sync/
      keyring.lgkkeys              group keyring (``keyring.py``), atomic writes
      devices/<device_id>.lgksync  one sealed view per device (``group.py``)
      signatures/<device_id>.lgksig  the writer's Ed25519 signature of that view
      witness/<device_id>.lgksync  witness file (format 2, no records) next to a format-1 view
      witness/<device_id>.lgksig   the writer's signature of that witness file
      removed/<device_id>.lgkremoved  signed removal notice of a removed device (``removal.py``)

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
   most 20 names; emergency access files (``heir_flow.is_heir_file``) are skipped
   silently; hidden ``.*.tmp`` files (in-flight atomic writes) are skipped
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
   Signatures (audit M-7, R-4): every view written by this version carries a
   signature file (``group.sign_view``).  The key a peer's signature must carry
   is, in this order: the ``signing_public`` of its entry in the accepted
   keyring (format 2, covered by the keyring MAC and by the member's own proof;
   ``keyring.member_signing_keys``), else its LAN-paired key (pinned by its QR
   pairing), else the key pinned on first use (``SyncGroupState.view_signers``).
   A peer with a keyring key or a pin needs a valid signature by that key, else
   its view is skipped as ``view-unsigned`` (no signature for this write: in
   flight, or written by someone else) or ``view-forged`` (a signature for this
   counter that does not match the file, or another key).  Every keyring key is
   pinned at once, and a pin changes only through the keyring: a keyring key
   that replaces a different pin is reported as ``signer-changed``.  First-use
   pinning remains only for members whose keyring entry has no key (a keyring
   or member from before format 2); views of devices that never signed (older
   apps) are accepted unsigned, as before.
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
9. Rollback witnesses (2026-10-29, ``witness.py``): every accepted peer view
   that is format 2, or format 1 with a matching witness file (same device,
   epoch and counter, zero records, signed by the key that signed the view),
   is checked with ``witness.check`` against this vault's generation
   (``session.generation``); the issues (``peer-vault-rollback``,
   ``vault-rollback``) join the report and ``peer_generations``,
   ``rollback_suspected`` and ``witness_peers`` are saved with ``last_seen``.
   A missing, stale or bad witness file is skipped silently for one run (a
   cloud client may upload it after the view); ``witness_counters`` records the
   view counter of each peer's last witnessed view, and once a peer is in
   ``witness_peers`` or has been witnessed before, a newer signed format-1 view
   that still has no matching witness file on the next run is reported as
   ``witness-missing`` (detail: the peer id), so deleting witness files cannot
   switch detection off unnoticed.  Gating: the own view is written as format 2
   only when every other member of the accepted keyring is in
   ``witness_peers``; otherwise it is format 1 and a witness file (and its
   signature) is written right after it, so older apps keep reading the
   folder.  A format-1 own file without a matching witness file, or a file in
   the other format than the gate asks for, is rewritten once; when the own
   view is current and only its witness file is missing or bad, just the
   witness file is written again (same counter, no state save).  A change of
   generation alone never rewrites the own file (each write saves the vault,
   which raises the generation again).
10. Removal notices (2026-10-30, ``removal.py``): every run writes the removal watch file next to
   the vault from the trusted state (deleted when the state is gone).  A run that stops without a
   trusted keyring adds ``removal-notice`` (detail: the signer) when a notice for this device verifies
   against the trusted keyring's member signing keys and the folder keyring no longer lists it; the
   app decides about erasing (``app.device_removal``).  ``rotate_folder_group`` writes a notice for
   each member in ``remove`` (never for the unconfirmed members it also drops).
11. Adopting a new epoch (here or by ``rotate_folder_group``) clears every
   peer's last-seen counter, digest and signing key: only members of the new
   epoch can write files for it, so a counter or key forged under the old key
   by a removed member stops mattering.

Joining, creating, rotating, leaving
------------------------------------
``create_folder_group``, ``join_folder_group``, ``rotate_folder_group`` and
``leave_folder_group`` are the UI entry points; they raise ``FolderSyncError``
with a stable ``reason`` (a ``KeyringError`` keeps its reason, a weak password
is ``weak-password``, an I/O error is ``folder-error``; the original exception
is the ``__cause__``).  Create makes a fresh device identity; so does join, except
that a vault that left this same group on this installation reuses its kept identity
(``vault_bridge.KeptIdentity``) when the keyring still lists it with the same keys and no
removal notice names it: its member entry is rewritten in place
(``keyring.rejoin_with_password``) and its view and hello counters continue, so the other
members see the same device again instead of a second one.
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
``leave_folder_group`` clears this device's sync state (keeping its identity and counters as
the kept identity) and keeps its own file
in the folder: the file may hold edits the other members have not merged yet
(the leaving device synced, then left before they ran), and deleting it would
lose those edits for the group.  It does NOT rotate (it cannot: rotating needs
a new password, and the leaving device should not hold the new key).  Its
keyring entry and its file stay until a remaining member rotates with
``remove=[that device]``, which deletes the file and stops it reading later
epochs.

Sync is not Pro-gated (licensing revision 2); this module has no licensing
dependency.

Share groups (sub-plan 07)
--------------------------
``FolderSync(root, install_id=..., share=<ShareGroup or group id>)`` runs a share group in its
own folder (same layout) instead of the personal group (``share_group.py`` holds its state):

* Pro only.  Without Pro only the keyring step below runs (a repair, an adoption, the owner's removal of
  this device: security actions, like removing a member), then the run stops with ``pro-required``: no
  view is read or written.  Never a licence (``licence_round`` is empty).
* Keyring: the folder's keyring is adopted with ``share_group.adopt_keyring`` (owner signature,
  pinned owner/collection/mode, growth-only within an epoch).  On the owner's device, a folder
  keyring that others grew while the owner's own approvals waited to be written is merged
  (``share_group.reconcile_owner_keyring``: approvals re-signed over the grown roster, the new
  joiners pending) and written (``keyring-merged``).  A missing keyring, or one this
  device's trusted keyring grows from (an older epoch, or fewer members/approvals), is replaced by
  the trusted one (``keyring-restored``).  Anyone who can write to the folder could otherwise stop
  the share for everyone (``share_group.restores_over``): the owner's device writes its trusted
  keyring back over any folder keyring it cannot adopt or reconcile, bytes that do not parse and a
  keyring naming another group included (only a later epoch signed by the pinned owner key is
  left alone; another group's keyring is reported as ``other-group-replaced``, so two owners writing
  over each other in one folder show up); a member's device writes back over a keyring of its trusted epoch that does not
  authenticate (MAC or owner signature).  An authenticated keyring of that epoch that does not grow
  (a concurrent join) still stops a member's run, and a member never writes over another group's
  keyring (``folder-has-other-group``).  A rotation that dropped this device: the owner's removal notice
  for it (``removed/``) is verified (pinned owner key only) and ``share_group.apply_share_removal``
  moves the collection's items to the trash and leaves the group (``share-removed``, detail: the
  collection id); without a valid notice the run stops with ``rejoin-required``.  A member whose
  pending join was lost to another join at the same moment (``share_group.superseded_join``)
  stops with ``superseded`` (join again).  Other refusals stop with their reason.
* Approval: a device the owner has not approved yet adopts the keyring and stops there
  (``awaiting-approval``): it merges no peer view and writes no own view.  Share v2 views are
  sealed with the content key (``share_group.view_key``) that only approved devices can open, so the
  share password alone opens no item; share v1 views are still sealed with the group key until the
  owner upgrades the share.  A keyring of a later format stops the run (``update-required``) and is
  never written over.
* Peers: only members the owner approved (and the owner), each view signed with its keyring
  key (the owner's with its pinned key).  Read-only shares: a member merges only the owner's view
  and the owner merges none, so only the owner's edits flow, whatever a member's file holds.
* ``run_merge`` with the share's ``collection_id`` (the vault bridge's namespace filter), then the
  own view (format 1, signed, no witness, documents never) under the reserved counter.
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
    READ_FORMATS,
    KeyringError,
    WeakSyncPassword,
    accept_keyring,
    approved_members,
    attach_with_password,
    create_for_existing_group,
    create_group,
    join_with_password,
    listed_with_key,
    member_names,
    member_signing_keys,
    open_with_device_wrap,
    parse_keyring,
    rejoin_with_password,
    rotate,
)
from .pairing import DeviceIdentity
from .runner import RunReport, SyncIssue, run_merge
from .attachment_flow import (collections_capable, folder_capable, import_missing, publish_folder_blobs,
                              referenced_blobs, write_capability, write_collections_capability)
from .attachment_sync import BlobFolder
from .vault_bridge import (
    publishable,
    _MAX_INT53,
    MAX_INSTALL_ID,
    MAX_MEMBERS_SEEN,
    MAX_PEERS_SEEN,
    TOMBSTONE_MAX_AGE_DAYS,
    KeptIdentity,
    SyncGroupState,
    _check_lease,
    clear_sync_state,
    epoch_reset_fields,
    kept_identity_for,
    licenses_in_views,
    load_sync_state,
    save_rejoined_state,
    save_sync_state,
)
from .witness import Observation, observation, own_witness, prune, session_generation
from .witness import check as witness_check
from . import removal, seen, witness_memory
from ..heir_flow import is_heir_file

SYNC_DIR_NAME = "LocalGateKeys Sync"
KEYRING_NAME = "keyring.lgkkeys"
DEVICES_DIR_NAME = "devices"
DEVICE_SUFFIX = ".lgksync"
SIGNATURES_DIR_NAME = "signatures"
SIGNATURE_SUFFIX = ".lgksig"
WITNESS_DIR_NAME = "witness"
#: A witness file holds no records; its header has at most 64 witness entries.
MAX_WITNESS_BYTES = 16 * 1024
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
    #: Generations and witnesses published with the accepted views (``witness.observation``).
    observations: tuple[Observation, ...] = ()
    #: device id -> view counter of every accepted view that published a generation (format 2 or witness).
    witnessed: dict[str, int] = field(default_factory=dict)
    #: device id -> view counter of every accepted signed format-1 view without a matching witness file.
    unwitnessed: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class OwnFile:
    """What this device's own file in the folder says (``FolderSync._own_file_status``)."""

    needs_write: bool
    counter: int = 0
    stale: bool = False
    present: bool = False
    #: The file carries a valid signature by this device's own key.
    self_signed: bool = False
    #: View format of the file (1 or 2), 0 when absent or unreadable.
    format: int = 0
    #: A format-1 file has a valid own-signed witness file for the same counter.
    witnessed: bool = False


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

    def __init__(self, root: Path | str, *, install_id: str, share: Any = None,
                 _kdf_override: tuple[int, int, int] | None = None) -> None:
        self.root = Path(root)
        self.install_id = _check_install(install_id)
        self._kdf_override = _kdf_override
        #: The share group this folder syncs (``share_group.ShareGroup`` or its id), None: the personal group.
        self.share_group_id: str | None = None
        if share is not None:
            group_id = share if isinstance(share, str) else getattr(share, "group_id", None)
            if not is_valid_id(group_id):
                raise ValueError("share group id is malformed")
            self.share_group_id = group_id

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

    @property
    def witness_dir(self) -> Path:
        return self.sync_dir / WITNESS_DIR_NAME

    def witness_file(self, device_id: str, suffix: str = DEVICE_SUFFIX) -> Path:
        if not is_safe_device_id(device_id):
            raise ValueError("unsafe device id")
        name = f"{device_id}{suffix}"
        path = self.witness_dir / name
        if path.parent != self.witness_dir or path.name != name:
            raise ValueError("witness file escapes the witness folder")
        return path

    def _read_witness(self, gk: GroupKey, view: View, signer: str) -> Observation | None:
        """The observation of a format-1 *view* from its witness file, or None (missing, stale, bad)."""
        dev = view.header["device_id"]
        try:
            path, sig_path = self.witness_file(dev), self.witness_file(dev, SIGNATURE_SUFFIX)
            if path.is_symlink() or sig_path.is_symlink():
                return None
            raw = _read_bounded(path, MAX_WITNESS_BYTES)
            sig = _read_bounded(sig_path, MAX_SIG_BYTES)
            witness = decode_view(gk, raw, expected_device_id=dev, max_bytes=MAX_WITNESS_BYTES, max_records=0)
            public = base64.b64encode(verify_view_signature(sig, raw, witness.header)).decode("ascii")
        except (OSError, ValueError):  # SyncFormatError is a ValueError
            return None
        if public != signer:
            return None
        return observation(view, witness)

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
        self, state: SyncGroupState, *, restore: bool = True
    ) -> tuple[list[SyncIssue], GroupKey | None, dict | None, bytes | None]:
        """(issues, key, ring, ring bytes); key None means the run must stop.

        *restore* False (licence-only runs) never writes the stored keyring back.
        """
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
            if restore and kind in _RESTORE_KINDS and not (isinstance(epoch, int) and epoch > trusted.epoch):
                restored = self._restore_keyring(state, trusted)
                if restored is not None:
                    return [SyncIssue("keyring-restored", detail)], restored[0], restored[1], state.keyring
            return [SyncIssue(kind, detail)], None, None, None
        return [], gk, ring, raw

    def _removal_issues(self, state: SyncGroupState, watch: Path | None) -> tuple[SyncIssue, ...]:
        """``removal-notice`` when a member this device trusted signed that it was removed (never raises).

        Checked only when the run stops without a trusted keyring; the watch file is refreshed from
        the trusted state first, so the app's locked check sees the same thing.
        """
        fresh = removal.watch_from_state(state, self.root)
        if fresh is None:
            return ()
        notice = removal.check(removal.refresh_watch(watch, fresh), install_id=self.install_id)
        return () if notice is None else (SyncIssue("removal-notice", notice.signer),)

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

    def write_removal_notice(self, identity: DeviceIdentity, group_id: str, device_id: str, epoch: int, *,
                             now: int) -> bool:
        """Write the signed notice that *device_id* was removed at *epoch*; False if it could not be written.

        Best effort: the rotation already happened; without the notice the removed device only stops
        syncing (it is never erased).
        """
        try:
            data = removal.make_notice(identity.signing_key, group_id=group_id, device_id=device_id,
                                       epoch=epoch, signer=identity.device_id, now=now)
            folder = self.sync_dir / removal.REMOVED_DIR_NAME
            folder.mkdir(exist_ok=True)
            _atomic_write(folder / removal.notice_name(device_id), data)
        except (OSError, removal.RemovalError):
            return False
        return True

    # --- device files ------------------------------------------------------------------

    def read_peers(self, gk: GroupKey, own_id: str, members: Iterable[str], last_seen: Mapping[str, int],
                   digests: Mapping[str, str], *, now: int, signers: Mapping[str, str] | None = None,
                   paired_keys: Mapping[str, str] | None = None,
                   keyring_keys: Mapping[str, str] | None = None) -> PeerRead:
        """Read every peer file; never raises for a single bad file (see module docstring).

        *keyring_keys*: each member's key from the accepted keyring (its views must be signed by it);
        *paired_keys*: the key a LAN-paired device's signature must carry when the keyring lists none;
        *signers*: keys pinned on first use (views must be signed by them).  Precedence in that order.
        """
        keyring_keys = keyring_keys or {}
        signers = {**(signers or {}), **keyring_keys}
        paired_keys = {**(paired_keys or {}), **keyring_keys}
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
        observed: list[Observation] = []
        witnessed: dict[str, int] = {}
        unwitnessed: dict[str, int] = {}
        try:
            names = sorted(entry.name for entry in os.scandir(self.devices_dir))
        except FileNotFoundError:
            return PeerRead(issues=tuple(issues))
        except OSError as exc:
            return PeerRead(issues=(*issues, SyncIssue("folder-unreadable", str(exc))))
        for name in names:
            if name.startswith(".") and name.endswith(".tmp"):
                continue  # an in-flight atomic write
            if is_heir_file(name):
                continue  # emergency access files (heir_flow), when its folder is this one: not a peer
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
            obs = observation(view)
            if obs is None and isinstance(signer, str):
                obs = self._read_witness(gk, view, signer)
            if obs is not None:
                observed.append(obs)
                witnessed[dev] = counter
            elif isinstance(signer, str):
                unwitnessed[dev] = counter
        if ignored:
            issues.append(_ignored_issue(ignored))
        return PeerRead(tuple(views), tuple(issues), seen, digs, signed, tuple(observed), witnessed, unwitnessed)

    def _check_signature(self, dev: str, name: str, raw: bytes, view: View, signers: Mapping[str, str],
                         paired_keys: Mapping[str, str], issues: list[SyncIssue]) -> str | bool | None:
        """The signing key (base64) of a validly signed view, None for an accepted unsigned one, False to skip.

        *paired_keys* already holds the keyring keys (which win), *signers* the pins and keyring keys.
        """
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
                  now: int, signing_key: ed25519.Ed25519PrivateKey | None = None,
                  vault_generation: int | None = None, witness: Mapping[str, int] | None = None,
                  inline: bool = False) -> None:
        """Encode and atomically write this device's own file, then its signature (if *signing_key*).

        With *vault_generation*: *inline* writes a format-2 view; otherwise the view stays format 1
        and a signed witness file follows it (``witness/``).
        """
        path = self.device_file(device_id)
        if vault_generation is not None and inline:
            raw = encode_view(gk, device_id, counter, states, now, vault_generation=vault_generation,
                              witness=witness or {})
        else:
            raw = encode_view(gk, device_id, counter, states, now)
        sig = sign_view(raw, signing_key) if signing_key is not None else None
        side = None
        if vault_generation is not None and not inline and signing_key is not None:
            side_raw = encode_view(gk, device_id, counter, (), now, vault_generation=vault_generation,
                                   witness=witness or {})
            side = (side_raw, sign_view(side_raw, signing_key))
        self.devices_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, raw)
        if sig is not None:
            self.signatures_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.signature_file(device_id), sig)
        if side is not None:
            self._write_witness_pair(device_id, *side)

    def write_witness(self, gk: GroupKey, device_id: str, counter: int, *, now: int,
                      signing_key: ed25519.Ed25519PrivateKey, vault_generation: int,
                      witness: Mapping[str, int]) -> None:
        """Write only the signed witness file for the own view at *counter* (the view is unchanged)."""
        raw = encode_view(gk, device_id, counter, (), now, vault_generation=vault_generation, witness=witness)
        self._write_witness_pair(device_id, raw, sign_view(raw, signing_key))

    def _write_witness_pair(self, device_id: str, raw: bytes, sig: bytes) -> None:
        self.witness_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.witness_file(device_id), raw)
        _atomic_write(self.witness_file(device_id, SIGNATURE_SUFFIX), sig)

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
        fmt = view.format
        witnessed = False
        if fmt == 1 and self_signed:
            own_key = base64.b64encode(state.identity().signing_public_key).decode("ascii")
            witnessed = self._read_witness(gk, view, own_key) is not None
        if own_states is None:
            return OwnFile(False, counter, stale, True, self_signed, fmt, witnessed)
        needs = (view.states != own_states or counter != state.own_counter or not self_signed
                 or written_at < now - OWN_REFRESH_SECONDS)
        return OwnFile(needs, counter, stale, True, self_signed, fmt, witnessed)

    # --- one run -----------------------------------------------------------------------

    def licence_round(self, session: Any, lease: Any, *, now: int) -> RunReport:
        """A licence-only run (free PC): read the peers' views, keep only the licences they carry.

        Writes nothing at all: no own view, witness, signature or capability
        file, no keyring restore, no document file import and no sync state;
        the vault is not touched.  The service offers ``licenses`` to
        ``licensing.adopt_synced_license``.  Because ``last_seen`` is never
        advanced, every round reads every peer view again.
        """
        _check_lease(session, lease)
        if self.share_group_id is not None:
            return RunReport()  # a share never carries a licence
        state = load_sync_state(session)
        if state is None:
            return RunReport(issues=(SyncIssue("not-joined"),))
        if state.install_id != self.install_id:
            return RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
        if not self._folder_exists():
            return RunReport(issues=(SyncIssue("folder-missing", str(self.sync_dir)),))
        issues, gk, ring, _raw = self._trusted_keyring(state, restore=False)
        if gk is None or ring is None:
            return RunReport(issues=tuple(issues) or (SyncIssue("keyring-corrupt"),))
        current = _member_ids(ring)
        known = set(state.members) if state.members_epoch == gk.epoch else set()
        members = current if len(known | current) > MAX_MEMBERS_SEEN else known | current
        ring_keys = {d: k for d, k in member_signing_keys(ring).items() if d != state.device_id}
        peers = self.read_peers(gk, state.device_id, members, state.last_seen, state.peer_digests, now=now,
                                signers={d: k for d, k in state.view_signers.items() if d != state.device_id},
                                paired_keys=_paired_keys(state), keyring_keys=ring_keys)
        issues.extend(peers.issues)
        _check_lease(session, lease)
        return RunReport(issues=tuple(issues), licenses=licenses_in_views(peers.views))

    def run_once(self, session: Any, lease: Any, *, now: int) -> RunReport:
        """One full folder sync; see the module docstring."""
        _check_lease(session, lease)
        if self.share_group_id is not None:
            return self._share_run(session, lease, now=now)
        state = load_sync_state(session)
        watch = _watch_path(session)
        if state is None:
            if watch is not None:
                removal.forget_watch(watch)  # left or reset: a later notice must not erase this vault
            return RunReport(issues=(SyncIssue("not-joined"),))
        if state.install_id != self.install_id:
            return RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
        if not self._folder_exists():
            return RunReport(issues=(SyncIssue("folder-missing", str(self.sync_dir)),))

        issues, gk, ring, ring_bytes = self._trusted_keyring(state)
        if gk is None or ring is None or ring_bytes is None:
            return RunReport(issues=(*(issues or (SyncIssue("keyring-corrupt"),)),
                                     *self._removal_issues(state, watch)))

        current = _member_ids(ring)
        unacked = _unacked_members(state, current)
        if watch is not None:  # what the app checks for a removal notice, also while locked
            trusted = removal.watch_from_state(dataclasses.replace(state, epoch=gk.epoch, keyring=ring_bytes,
                                                                   unacked_members=unacked), self.root)
            if trusted is not None:
                removal.refresh_watch(watch, trusted)
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
        ring_keys = {d: k for d, k in member_signing_keys(ring).items() if d != state.device_id}
        for device_id, key in sorted(ring_keys.items()):
            pinned = state.view_signers.get(device_id)
            if pinned is not None and pinned != key:
                issues.append(SyncIssue("signer-changed", f"{device_id}: the keyring lists another signing key"))
        peers = self.read_peers(gk, state.device_id, members, state.last_seen, state.peer_digests, now=now,
                                signers={d: k for d, k in state.view_signers.items() if d != state.device_id},
                                paired_keys=_paired_keys(state), keyring_keys=ring_keys)
        issues.extend(peers.issues)
        blobs = BlobFolder(self.sync_dir)
        # Document files first: a document is applied only once its file was imported.
        issues.extend(import_missing(session, lease, [s for v in peers.views for s in v.states],
                                     lambda ref: blobs.read(ref.blob)))
        # Personal collections sync only when every other member wrote a valid signed collections
        # capability file: the view file is read by all of them (an older app would refuse the states).
        col_signers = {**state.view_signers, **peers.signers, **ring_keys}
        collections = all(collections_capable(self.sync_dir, gk, d, col_signers.get(d))
                          for d in current - {state.device_id})
        report = run_merge(session, lease, device_id=state.device_id, views=peers.views, now=now,
                           collections=collections)
        issues.extend(report.issues)
        _check_lease(session, lease)
        own_generation = session_generation(session)
        # The session's LAN checks may be ahead of the stored generations (lan_sync saves them throttled).
        mem = witness_memory.memory(session, state.group_id, state.device_id)
        checked = witness_check(state.device_id, own_generation, peers.observations if own_generation is not None
                                else (), witness_memory.merged(state.peer_generations, mem),
                                state.rollback_suspected)
        issues.extend(checked.issues)
        witness_keep = (members | {p.get("device_id") for p in state.lan_peers}) - {state.device_id}
        peer_generations = prune(checked.peer_generations, witness_keep)
        if mem is not None:
            mem.generations = dict(peer_generations)
        witness_peers = tuple(prune(dict.fromkeys((*state.witness_peers, *checked.capable), 0), witness_keep))
        # A peer known to publish its generation (witness_peers, or a witness seen from it before)
        # whose newer view comes without one: the witness file was deleted, damaged or withheld.
        # One run of grace (the view was already there last run) covers a cloud client that
        # uploads the witness file after the view.
        known_witnessing = set(witness_peers) | set(state.witness_counters)
        for dev, ctr in sorted(peers.unwitnessed.items()):
            if (dev in known_witnessing and ctr > state.witness_counters.get(dev, -1)
                    and state.last_seen.get(dev) == ctr):
                issues.append(SyncIssue("witness-missing", dev))
        witness_counters = {**state.witness_counters, **peers.witnessed}
        witness_counters = {d: c for d, c in witness_counters.items() if d in witness_keep}
        if len(witness_counters) > MAX_PEERS_SEEN:
            witness_counters = dict(sorted(witness_counters.items())[:MAX_PEERS_SEEN])
        others = current - {state.device_id}
        inline = own_generation is not None and bool(others) and others <= set(witness_peers)

        identity = state.identity()
        own_key = base64.b64encode(identity.signing_public_key).decode("ascii")
        last_seen = {**state.last_seen, **peers.seen}
        digests = {**state.peer_digests, **peers.digests}
        # Keyring keys are pinned at once (re-pinning happens only here, from the accepted keyring).
        signers = {**state.view_signers, **peers.signers, **ring_keys}
        if len(last_seen) > MAX_PEERS_SEEN or len(digests) > MAX_PEERS_SEEN or len(signers) > MAX_PEERS_SEEN:
            last_seen = {d: c for d, c in last_seen.items() if d in members}
            digests = {d: h for d, h in digests.items() if d in members}
            signers = {d: k for d, k in signers.items() if d in members}
        # Documents are published only when every other member wrote a valid signed capability file.
        documents = all(folder_capable(self.sync_dir, gk, d, signers.get(d)) for d in others)
        # The emergency access plan only when every other member advertised the heir feature (sub-plan 08).
        heir = all(folder_capable(self.sync_dir, gk, d, signers.get(d), feature="heir") for d in others)
        if report.own_states is not None:
            report = dataclasses.replace(report, own_states=publishable(report.own_states, documents=documents,
                                                                        heir=heir))
        new_state = dataclasses.replace(state, last_seen=last_seen, peer_digests=digests,
                                        members_epoch=gk.epoch, members=tuple(sorted(members)),
                                        keyring=ring_bytes, unacked_members=unacked, view_signers=signers,
                                        peer_generations=peer_generations,
                                        rollback_suspected=checked.rollback_suspected,
                                        witness_peers=witness_peers, witness_counters=witness_counters)
        # A peer whose newer view was accepted this run was synced with now (local only).
        accepted = [d for d, c in peers.seen.items() if d != state.device_id and c > state.last_seen.get(d, -1)]
        new_state = new_state.synced_with(accepted, int(now))
        own = self._own_file_status(gk, state, report.own_states, now)
        needs_write, file_counter = own.needs_write, own.counter
        witness_only = False
        if report.own_states is not None and own.present and (
                (own.format == 1 and own_generation is not None and (inline or not own.witnessed)) or (own.format == 2 and not inline)):
            if own.format == 1 and not inline and own.self_signed and own.counter == state.own_counter:
                witness_only = not needs_write  # only the witness file is missing or bad: rewrite just it
            else:
                needs_write = True  # publish the witness once, in the form every member can read
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
        try:
            write_capability(self.sync_dir, gk, state.device_id, identity.signing_key, own_key, now=now)
            write_collections_capability(self.sync_dir, gk, state.device_id, identity.signing_key, own_key,
                                         now=now)
            write_capability(self.sync_dir, gk, state.device_id, identity.signing_key, own_key, now=now,
                             feature="heir")
        except (OSError, ValueError) as exc:
            issues.append(SyncIssue("write-failed", f"capability: {exc}"))
        # Heartbeats: when each device last ran here, even with no changes (shown on the sync status only).
        try:
            seen.write_heartbeat(self.sync_dir, gk, state.device_id, identity.signing_key, now=int(now))
        except (OSError, ValueError, SyncFormatError) as exc:
            issues.append(SyncIssue("write-failed", f"heartbeat: {exc}"))
        trusted = {**signers, **_paired_keys(state), **ring_keys}
        seen.read_peers(self.sync_dir, gk, state.group_id, sorted(d for d in others if is_safe_device_id(d)),
                        trusted, now=int(now))
        if needs_write and report.own_states is not None and documents:
            issues.extend(publish_folder_blobs(session, blobs, report.own_states, now=now))  # before the view
        if report.own_states is not None and others <= {v.header["device_id"] for v in peers.views}:
            # Every member's view was read: a blob none of them references can go (after 7 days).
            blobs.sweep(referenced_blobs([report.own_states, *(v.states for v in peers.views)]), now=now)
        if needs_write and report.own_states is not None:
            _check_lease(session, lease)
            try:
                self.write_own(gk, state.device_id, report.own_states, counter, now=now,
                               signing_key=identity.signing_key,
                               vault_generation=session_generation(session),
                               witness=own_witness(new_state.peer_generations, witness_keep, state.device_id),
                               inline=inline)
                wrote = True
            except SyncFormatError as exc:
                issues.append(SyncIssue("too-large", str(exc)))
            except (OSError, ValueError) as exc:
                issues.append(SyncIssue("write-failed", str(exc)))
        elif witness_only and own_generation is not None:
            # The view itself is current: write only its witness file (same counter), so a deleted
            # witness costs one small write per run and never a counter bump or a vault save.
            _check_lease(session, lease)
            try:
                self.write_witness(gk, state.device_id, file_counter, now=now, signing_key=identity.signing_key,
                                   vault_generation=own_generation,
                                   witness=own_witness(new_state.peer_generations, witness_keep, state.device_id))
            except (OSError, ValueError) as exc:
                issues.append(SyncIssue("write-failed", str(exc)))
        return dataclasses.replace(report, issues=tuple(issues), wrote=wrote)


    # --- share groups (module docstring "Share groups") -------------------------------

    def publish_share_notice(self, device_id: str, notice: bytes) -> bool:
        """Write the owner's removal *notice* for *device_id* (``share_group.remove_member``); False on failure."""
        try:
            folder = self.sync_dir / removal.REMOVED_DIR_NAME
            folder.mkdir(parents=True, exist_ok=True)
            _atomic_write(folder / removal.notice_name(device_id), notice)
        except (OSError, removal.RemovalError):
            return False
        return True

    def _share_removed(self, session: Any, lease: Any, state: SyncGroupState, folder_raw: bytes,
                       reason: str) -> RunReport:
        """The folder's keyring no longer lets this device in: act on the owner's notice, if there is one."""
        from . import share_group as sg

        collection_id = sg.share_info(session, state.group_id)["collection_id"]
        notice = self._read_share_notice(state.device_id)
        if notice is None:
            return RunReport(issues=(SyncIssue("rejoin-required", reason),))
        _check_lease(session, lease)
        try:
            sg.apply_share_removal(session, state.group_id, notice, folder_raw)
        except removal.RemovalError as exc:
            return RunReport(issues=(SyncIssue("rejoin-required", f"{reason}; notice refused ({exc.reason})"),))
        except sg.ShareGroupError as exc:  # trash or history full: nothing changed, the next run retries
            return RunReport(issues=(SyncIssue(exc.reason, str(exc)),))
        return RunReport(issues=(SyncIssue("share-removed", collection_id),))

    def _read_share_notice(self, device_id: str) -> bytes | None:
        """The removal notice for *device_id* in the folder, None when missing or unreadable (folder I/O only)."""
        try:
            path = self.sync_dir / removal.REMOVED_DIR_NAME / removal.notice_name(device_id)
            return _read_bounded(path, removal.MAX_NOTICE_BYTES)
        except (OSError, removal.RemovalError):
            return None

    def _share_keyring(self, session: Any, lease: Any, state: SyncGroupState,
                       issues: list[SyncIssue]) -> RunReport | None:
        """Bring the folder keyring and the trusted one together; a report means the run stops."""
        from . import share_group as sg

        stored = state.keyring
        if stored is None:
            return RunReport(issues=(SyncIssue("keyring-corrupt", "no trusted keyring"),))
        try:
            raw: bytes | None = self.read_keyring_bytes()
        except FileNotFoundError:
            raw = None
        except OSError as exc:
            return RunReport(issues=(SyncIssue("keyring-unreadable", str(exc)),))
        if raw == stored:
            return None
        kdf = self._kdf_override
        folder_ring: dict | None = None
        other_group = False
        if raw is not None:
            try:
                folder_ring = parse_keyring(raw)
                if type(folder_ring.get("format")) is int and folder_ring["format"] > max(READ_FORMATS):
                    # A later app version wrote it: never write an older keyring over it.
                    return RunReport(issues=(SyncIssue("update-required", KEYRING_NAME),))
            except KeyringError as exc:
                # Bytes that do not parse: the owner writes its keyring back; a member waits for it.
                if not sg.restores_over(session, state.group_id, raw, _kdf_override=kdf):
                    return RunReport(issues=(SyncIssue("keyring-corrupt", str(exc)),))
                folder_ring = None
            if folder_ring is not None and folder_ring.get("group_id") != state.group_id:
                if not sg.restores_over(session, state.group_id, raw, _kdf_override=kdf):
                    return RunReport(issues=(SyncIssue("folder-has-other-group", KEYRING_NAME),))
                other_group = isinstance(folder_ring.get("group_id"), str)
                folder_ring = None
        if raw is not None and folder_ring is not None:
            try:
                _check_lease(session, lease)
                sg.adopt_keyring(session, state.group_id, raw, _kdf_override=self._kdf_override)
                return None
            except sg.ShareGroupError as exc:
                if exc.reason == "removed":
                    return self._share_removed(session, lease, state, raw, exc.reason)
                return RunReport(issues=(SyncIssue(exc.reason, str(exc)),))
            except KeyringError as exc:
                _check_lease(session, lease)
                if sg.reconcile_owner_keyring(session, state.group_id, raw, _kdf_override=self._kdf_override):
                    # The owner's approvals, re-signed over the folder's grown roster: write that.
                    stored = sg.share_keyring(session, state.group_id)
                    issues.append(SyncIssue("keyring-merged", KEYRING_NAME))
                elif sg.grows_from(folder_ring, parse_keyring(stored)):
                    pass  # the folder is behind this device: the trusted keyring is written back below
                elif sg.superseded_join(session, state.group_id, raw, _kdf_override=self._kdf_override):
                    # Someone joined at the same moment and this device's join was lost: join again.
                    return RunReport(issues=(SyncIssue("superseded", state.group_id),))
                elif sg.restores_over(session, state.group_id, raw, _kdf_override=kdf):
                    pass  # the owner's keyring over anything else; a member's over a copy that fails to authenticate
                else:
                    if exc.reason in _REJOIN_REASONS:
                        return self._share_removed(session, lease, state, raw, exc.reason)
                    return RunReport(issues=(SyncIssue(_keyring_kind(exc.reason), str(exc)),))
        try:
            self.write_keyring(parse_keyring(stored), expected=raw)
        except FolderSyncError as exc:
            return RunReport(issues=(SyncIssue(exc.reason, str(exc)),))
        except OSError as exc:
            return RunReport(issues=(SyncIssue("write-failed", f"keyring: {exc}"),))
        if raw is not None and not any(i.kind == "keyring-merged" for i in issues):
            # Another share's keyring that the owner replaced is said apart (final review A1): two owners
            # of different groups in one folder would otherwise overwrite each other without a word.
            issues.append(SyncIssue("other-group-replaced" if other_group else "keyring-restored", KEYRING_NAME))
        return None

    def _share_run(self, session: Any, lease: Any, *, now: int) -> RunReport:
        """One run of a share group's folder (module docstring "Share groups")."""
        from . import share_group as sg

        group_id = self.share_group_id
        if group_id is None:
            return RunReport(issues=(SyncIssue("not-joined"),))
        try:
            info = sg.share_info(session, group_id)
            state = sg.share_state(session, group_id)
        except sg.ShareGroupError as exc:
            kind = "not-joined" if exc.reason == "not-joined" else "state-corrupt"
            return RunReport(issues=(SyncIssue(kind, group_id),))
        pro = sg.share_sync_allowed()
        if state.install_id != self.install_id:
            return RunReport(issues=(SyncIssue("rejoin-required", "install-mismatch"),))
        if not self.root.is_dir():
            return RunReport(issues=(SyncIssue("folder-missing", str(self.root)),))
        issues: list[SyncIssue] = []
        stop = self._share_keyring(session, lease, state, issues)
        if not pro:
            # Pro ended: the keyring step above still ran (a repair is a security action, like removing a
            # member, final review A2); no view is read or written.
            reported = stop.issues if stop is not None else tuple(issues)
            return RunReport(issues=(*reported, SyncIssue("pro-required", group_id)))
        if stop is not None:
            return stop
        _check_lease(session, lease)
        state = sg.share_state(session, group_id)
        ring = parse_keyring(state.keyring)  # trusted: written or adopted above
        own, owner = state.device_id, info["owner"]
        approved = set(approved_members(ring) or ()) | {owner}
        try:
            # Share v2: the content key only approved devices hold; share v1: the group key.
            gk = sg.view_key(session, group_id) if own in approved else None
        except KeyringError as exc:
            return RunReport(issues=(*issues, SyncIssue("tampered", str(exc))))
        if gk is None:
            # Not approved yet: the keyring was adopted above, but no peer view is merged and no own
            # view is written until the owner lets this device in (share v2: it cannot open them either).
            issues.append(SyncIssue("awaiting-approval", group_id))
            return RunReport(issues=tuple(issues))
        if info["shared_mode"] == "read":
            members = {owner} - {own}  # only the owner's edits flow; the owner reads nobody
        else:
            members = approved - {own}
        members = {d for d in members if is_safe_device_id(d)}
        ring_keys = {d: k for d, k in member_signing_keys(ring).items() if d in members}
        if owner in members:
            ring_keys[owner] = info["owner_key"]
        peers = self.read_peers(gk, own, members, state.last_seen, state.peer_digests, now=now,
                                signers={d: k for d, k in state.view_signers.items() if d in members},
                                keyring_keys=ring_keys)
        issues.extend(peers.issues)
        report = run_merge(session, lease, device_id=own, views=peers.views, now=now,
                           known_devices=approved | set(state.last_seen), collection_id=info["collection_id"])
        issues.extend(report.issues)
        _check_lease(session, lease)
        identity = state.identity()
        own_key = base64.b64encode(identity.signing_public_key).decode("ascii")
        keep = approved | {own}
        last_seen = {d: c for d, c in {**state.last_seen, **peers.seen}.items() if d in keep}
        digests = {d: h for d, h in {**state.peer_digests, **peers.digests}.items() if d in keep}
        signers = {d: k for d, k in {**state.view_signers, **peers.signers, **ring_keys}.items() if d in keep}
        new_state = dataclasses.replace(state, last_seen=last_seen, peer_digests=digests, view_signers=signers)
        accepted = [d for d, c in peers.seen.items() if c > state.last_seen.get(d, -1)]
        new_state = new_state.synced_with(accepted, int(now))
        own_file = self._own_file_status(gk, state, report.own_states, now)
        file_counter = own_file.counter
        if own_file.present and not own_file.self_signed and file_counter > state.own_counter:
            issues.append(SyncIssue("own-file-rewritten", f"{own}{DEVICE_SUFFIX}"))
            if file_counter - state.own_counter > MAX_COUNTER_JUMP:
                file_counter = state.own_counter
        counter = max(state.own_counter, file_counter) + 1
        needs_write = own_file.needs_write and report.own_states is not None
        if needs_write and counter > _MAX_INT53:
            issues.append(SyncIssue("counter-exhausted", f"own counter {counter - 1}"))
            needs_write = False
        if needs_write:
            new_state = dataclasses.replace(new_state, own_counter=counter,
                                            view_signers={**new_state.view_signers, own: own_key})
        if new_state != state:
            _check_lease(session, lease)
            sg.save_share_state(session, group_id, new_state)  # reserve the counter before writing
        wrote = False
        if needs_write and report.own_states is not None:
            _check_lease(session, lease)
            try:
                self.write_own(gk, own, report.own_states, counter, now=now, signing_key=identity.signing_key)
                wrote = True
            except SyncFormatError as exc:
                issues.append(SyncIssue("too-large", str(exc)))
            except (OSError, ValueError) as exc:
                issues.append(SyncIssue("write-failed", str(exc)))
        return dataclasses.replace(report, issues=tuple(issues), wrote=wrote)


def _watch_path(session: Any) -> Path | None:
    """The removal watch file next to the session's vault (``removal.watch_path``), if it has one."""
    path = getattr(session, "path", None)
    return removal.watch_path(path) if isinstance(path, (str, os.PathLike)) else None


_epoch_reset = epoch_reset_fields  # moved to vault_bridge (shared with share groups)


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


def _may_rejoin(fs: FolderSync, ring: Mapping[str, Any], kept: KeptIdentity) -> bool:
    """Whether a join may reuse *kept*: the keyring still lists it with its keys and no removal notice names it.

    A keyring that does not list it (a rotation dropped it), lists it with another key, or a removal
    notice for it in the folder (checked by name only: a planted one can only cost the old id) all mean
    the kept identity is not used again (rule 6).
    """
    identity = kept.identity()
    if not listed_with_key(ring, identity) or not is_safe_device_id(kept.device_id):
        return False
    notice = fs.sync_dir / removal.REMOVED_DIR_NAME / removal.notice_name(kept.device_id)
    try:
        return not notice.exists()
    except OSError:
        return False


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
    """Join the group in *root* with the sync password, then run once.

    The device identity is fresh, or the kept one when this vault left this same group on this
    installation and the folder still lists that identity with its keys (``_may_rejoin``).  Any
    join of the kept group drops the kept identity.

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
        if "metadata" in ring:
            # A shared collection's keyring (sub-plan 07): joining it as device sync would publish
            # every personal item to the people it is shared with.
            raise FolderSyncError("share-group", "this folder holds a shared collection, not device sync")
        state = load_sync_state(session)
        # The identity this vault had in this group before it left (rule 3); only when not joined.
        kept = kept_identity_for(session, ring.get("group_id"), install_id) if state is None else None
        with free():
            if state is not None:
                if state.group_id != ring.get("group_id"):
                    raise FolderSyncError("different-group", "this vault already syncs with another group")
                if state.install_id == install_id and _healthy_member(ring, state, _kdf_override):
                    raise FolderSyncError("already-joined", "this vault is already a member")
            reuse = kept is not None and _may_rejoin(fs, ring, kept)
            if reuse:
                # Same id, same keys: the member entry is rewritten in place (rule 6).
                identity = kept.identity()
                new_ring, gk = rejoin_with_password(ring, password, identity, device_name,
                                                    _kdf_override=_kdf_override)
            else:
                identity = DeviceIdentity.generate()
                new_ring, gk = join_with_password(ring, password, identity, device_name,
                                                  _kdf_override=_kdf_override)
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
        if reuse:
            # Peers refuse a file of this id whose counter is not above the last one they accepted.
            new_state = kept.continue_counters(new_state)
        _check_lease(session, lease)
        # Joining the kept group drops the kept identity either way: it is live again, or this folder
        # says it can no longer be used (removed, another key) and the join made a new one.
        save_rejoined_state(session, new_state, drop_kept=kept is not None)
        if same and state.install_id == install_id:
            # Our previous identity's file on this installation is obsolete.
            with free(), contextlib.suppress(OSError, ValueError):
                fs.device_file(state.device_id).unlink()
            with free(), contextlib.suppress(OSError, ValueError):
                fs.signature_file(state.device_id).unlink()
            for suffix in (DEVICE_SUFFIX, SIGNATURE_SUFFIX):
                with free(), contextlib.suppress(OSError, ValueError):
                    fs.witness_file(state.device_id, suffix).unlink()
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
            # Only members the user chose get a signed removal notice (never the unconfirmed ones below).
            notify = sorted({d for d in drop if d in _member_ids(ring) and d != state.device_id})
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
                for suffix in (DEVICE_SUFFIX, SIGNATURE_SUFFIX):
                    with contextlib.suppress(FileNotFoundError):
                        fs.witness_file(dev, suffix).unlink()
            for dev in notify:
                if is_safe_device_id(dev):
                    fs.write_removal_notice(identity, state.group_id, dev, gk.epoch, now=_now(now))
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
    """Clear this vault's sync state, keeping its identity for a rejoin; its own file stays in the folder.

    The identity and its counters are kept (``vault_bridge.KeptIdentity``) only for a state joined
    on this installation and never in the duress vault; a later Leave replaces it.

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
    # Keep the identity so a later join of this same group comes back under the same device id
    # (rule 1).  Only an identity joined on this installation: a vault copied from another PC must
    # never reuse that PC's id.  The duress vault never keeps one.
    from ..duress import is_decoy

    keep = None
    if state.install_id == install_id and not is_decoy(session):
        keep = KeptIdentity.of(state)
    _check_lease(session, lease)
    clear_sync_state(session, keep=keep)
    return True


__all__ = [
    "DEVICE_SUFFIX", "KEYRING_NAME", "MAX_COUNTER_JUMP", "MAX_FILE_COUNTER", "OWN_REFRESH_DAYS", "SIGNATURE_SUFFIX",
    "SIGNATURES_DIR_NAME", "SYNC_DIR_NAME", "FolderSync", "FolderSyncError", "counter_verdict",
    "PeerRead", "RunReport", "SyncIssue", "acknowledge_members", "add_folder_to_group", "attach_folder", "create_folder_group", "is_safe_device_id", "join_folder_group",
    "leave_folder_group", "rotate_folder_group",
]
