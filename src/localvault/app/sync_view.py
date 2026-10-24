"""Sync screen view-models, wording and background jobs (no UI toolkit)."""
from __future__ import annotations

import ipaddress
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..password_tools import STRENGTH_LABELS, estimate_strength
from ..sync.keyring import UNNAMED_DEVICE
from ..sync.lan_address import is_lan_address

#: Fixed port suggested for this PC's Wi-Fi sync listener.
DEFAULT_LAN_PORT = 47821


#: Longest device or item name shown on the screen (characters, including the ellipsis).
NAME_LIMIT = 40


#: Sync password rules (``sync/keyring.py``): length and ``estimate_strength`` score.
MIN_SYNC_PASSWORD_LEN = 12


MIN_SYNC_PASSWORD_SCORE = 3


#: Peer files older than this are stale (``folder_transport.STALE_AFTER_SECONDS``).
STALE_AFTER_SECONDS = 365 * 86400


PASSWORD_ADVICE = "Write this password down. Never reuse an earlier sync password."  # noqa: S105 - user copy


LEAVE_TEXT = (
    "Leave sync on this PC?\n\n"
    "This PC stops syncing. Your items stay on this PC. Its last sync file stays in the sync folder, "
    "so your other devices still receive the changes made here.\n\n"
    "On one of your other devices, open Sync and remove this PC (Remove a device). That deletes its "
    "file and changes the sync password, so this PC can no longer read anything new."
)


LEAVE_WIFI_TEXT = (
    "Leave sync on this PC?\n\n"
    "This PC stops Wi-Fi sync and forgets its paired devices. Your items stay on this PC.\n\n"
    "On your other devices, remove this PC from their paired devices. To sync again, pair again with a QR code."
)


#: "Copy code text" is cleared from the clipboard after this long (if it still holds the code).
QR_CLIPBOARD_SECONDS = 120


RESET_TEXT_1 = (
    "Reset sync on this PC?\n\n"
    "This forgets this vault's sync group, its keys and its sync history. Your items stay on this PC. "
    "To sync again you join a folder or pair again."
)


RESET_TEXT_2 = "Are you sure? This cannot be undone. Reset sync on this PC now?"


LAN_ONLY_FOLDER_HINT = (
    "To sync through a cloud folder too, add one to this group with a new sync password, or use the folder "
    "another device in this group already added. Your Wi-Fi pairings stay as they are."
)


def leave_text(group: Any) -> str:
    """Leave confirmation: the cloud-folder text, or the Wi-Fi-only text for a group without a folder."""
    return LEAVE_TEXT if getattr(group, "folder_path", None) else LEAVE_WIFI_TEXT


def remove_wifi_device_text(name: str) -> str:
    """Confirmation for removing a Wi-Fi-only paired device (no sync password to change)."""
    return (f"Remove {name} from Wi-Fi sync?\n\nIt stops syncing with this PC but keeps what it already has.\n\n"
            f"Wi-Fi pairing is per PC: also remove {name} on every other PC it is paired with, or it keeps "
            "syncing with those PCs.")


def reset_result_text(cleared: bool | None) -> str:
    if cleared is None:
        return "Sync could not be reset on this PC. Details are in the error log. Try again after unlocking."
    return "Sync was reset on this PC." if cleared else "There was nothing to reset."


def should_clear_clipboard(current: Any, payload: str) -> bool:
    """Clear the copied pairing code only if the clipboard still holds exactly that text."""
    return isinstance(current, str) and current == payload


def rotation_intro(group: Any, *, removing: str | None = None) -> str:
    """Copy for a password change (rotation), naming QR-paired devices that must pair again."""
    text = ("Enter a NEW sync password. Your other cloud-folder devices pick up the change on their next sync; "
            "a device set up later joins with the new password.")
    peers = [p for p in getattr(group, "lan_peers", ()) or () if p.device_id != removing]
    if peers:
        names = group.names() if hasattr(group, "names") else {}
        shown = ", ".join(sanitize_name(names.get(p.device_id) or short_id(p.device_id)) for p in peers)
        text += ("\n\nDevices paired by QR code can't follow a password change and must be paired again "
                 f"afterwards: {shown}.")
    plan = rotation_plan(group, removing=() if removing is None else (removing,))
    if plan.text:
        text += "\n\n" + plan.text
    return text


@dataclass(frozen=True)
class RotationPlan:
    """Who gets the new key in a rotation (audit M10): the confirmed members the user is shown.

    ``keep`` goes to ``rotate_folder_group(keep=...)``; any other keyring member (one
    not confirmed, or one that appeared after this was shown) is dropped there.
    """

    keep: tuple[str, ...] | None  # None: no member list to show; the library default applies
    text: str


def _member_name(group: Any, device_id: str) -> str:
    names = group.names() if hasattr(group, "names") else {}
    return sanitize_name(names.get(device_id) or short_id(device_id))


def rotation_plan(group: Any, *, removing: Iterable[str] = ()) -> RotationPlan:
    """The keep-list and its copy for a rotation that removes *removing*.

    Members still unconfirmed (``member-added``) are left out of the keep-list:
    they lose access unless the user confirmed them first.
    """
    members = tuple(getattr(group, "members", ()) or ())
    if not members:
        return RotationPlan(None, "")
    gone = set(removing)
    unacked = set(getattr(group, "unacked", ()) or ())
    keep = tuple(m.device_id for m in members
                 if not m.is_self and m.device_id not in gone and m.device_id not in unacked)
    shown = [_member_name(group, d) for d in keep] + ["this PC"]
    text = f"The new sync key goes only to: {', '.join(shown)}."
    lose = [_member_name(group, m.device_id) for m in members
            if m.device_id in unacked and m.device_id not in gone and not m.is_self]
    if lose:
        text += (f" Not confirmed, so they lose access: {', '.join(lose)}. To keep one, cancel and choose "
                 "These are my devices first.")
    return RotationPlan(keep, text)


def lan_removed_folder_text(group: Any) -> str:
    """Confirmation for adding a cloud folder after a Wi-Fi device was removed (audit M9)."""
    peers = [p.device_id for p in getattr(group, "lan_peers", ()) or ()]
    text = ("A Wi-Fi device was removed from this group, and it still knows the current sync key. So the cloud "
            "folder gets a NEW key instead, and the removed device cannot read it.")
    if peers:
        shown = ", ".join(_member_name(group, d) for d in peers)
        text += (f"\n\nYour other paired devices can't receive a new key over Wi-Fi: {shown}. Afterwards pair "
                 "each of them again (leave sync there, then scan a new QR code), or use Join a folder there with "
                 "the new sync password. Until then they don't sync with this PC.")
    return text + "\n\nContinue?"


def sanitize_name(value: Any, limit: int = NAME_LIMIT) -> str:
    """Display form of a device or item name: no control/format characters, one space, at most *limit*."""
    if not isinstance(value, str):
        value = ""
    out: list[str] = []
    for ch in value:
        category = unicodedata.category(ch)
        if ch in "\r\n\t" or category == "Zs" or category in ("Zl", "Zp"):
            out.append(" ")
        elif category.startswith("C"):  # Cc control, Cf format (bidi overrides), Cs, Co, Cn
            continue
        else:
            out.append(ch)
    text = " ".join("".join(out).split())
    if not text:
        return UNNAMED_DEVICE
    if len(text) > limit:
        text = text[: max(1, limit - 1)].rstrip() + "…"
    return text


def default_device_name() -> str:
    """This PC's name for the keyring: the generic ``DEFAULT_DEVICE_NAME_PC``, never the host name."""
    from ..sync.keyring import DEFAULT_DEVICE_NAME_PC

    return DEFAULT_DEVICE_NAME_PC


def short_id(device_id: str) -> str:
    return f"Device {sanitize_name(device_id, limit=9)[:8]}"


#: User copy per issue kind; ``{subject}`` is the file or device the issue is about.
ISSUE_COPY: Mapping[str, str] = {
    # keyring and membership (cloud folder)
    "keyring-restored": "The sync folder had an older or altered key file. This PC put the trusted copy back; "
                        "sync continues.",
    "folder-has-other-group": "This sync folder now holds a different sync group. Sync stopped and nothing was "
                              "written. Leave sync, or reset sync on this PC, then join the right folder.",
    "rotation-conflict": "Two devices changed the sync password at the same time. Sync stopped. Join the folder "
                         "again with the newest sync password.",
    "removed-or-conflict": "This device may have been removed from sync. Re-join if that isn't expected.",
    "rejoin-required": "This PC must join sync again (it missed a password change, or it was removed). Join the "
                       "folder again with the current sync password.",
    "member-dropped": "{subject} disappeared from the member list without a password change. If you did not "
                      "remove it, change the sync password.",
    "member-added": "{subject} was added to this sync group by another device. If it is yours, choose These are "
                    "my devices. If not, remove it (Remove a device): the new sync password goes only to devices "
                    "you confirmed.",
    "old-key-known": "A Wi-Fi device removed from this PC still knows the current sync key and could read the "
                     "cloud folder. Change the sync password to cut it off.",
    "tampered": "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync "
                "on this PC and join again.",
    "keyring-corrupt": "The key file in the sync folder is damaged. Reset sync on this PC, or restore the folder.",
    "keyring-missing": "The key file in the sync folder is missing. Check the folder, or reset sync on this PC.",
    "keyring-unreadable": "The key file in the sync folder could not be read. Check that the cloud app has "
                          "downloaded it.",
    "unsafe-member": "A device in the member list has a name that is not a safe file name; it is ignored.",
    "bad-name": "The name of {subject} in the key file could not be read; it is shown as Unnamed device. "
                "Sync continues.",
    "state-corrupt": "This vault's sync settings are damaged. Reset sync on this PC, then join again.",
    "identity-mismatch": "This PC's sync identity does not match its pairing. Reset sync on this PC and pair "
                         "again.",
    "not-joined": "Sync is not set up on this PC.",
    # device files
    "stale-self": "This PC had not synced for over a year. Items deleted elsewhere more than a year ago may come "
                  "back; delete them again if they do.",
    "stale-device": "{subject} has not synced for over a year and is ignored. Remove that device if it is gone.",
    "ignored-file": "Unknown files in the sync folder were ignored ({subject}). Cloud apps sometimes make copies "
                    "like these; you can delete them.",
    "corrupt": "{subject} is damaged or could not be verified and was skipped. Nothing was changed.",
    "keyring-rollback": "The key file in the sync folder was replaced by an older copy and could not be put "
                        "back. Sync stopped. Check the folder, or reset sync on this PC and join again.",
    "rollback": "{subject} was replaced by an older copy (for example from the cloud's file history) and was "
                "skipped.",
    "suspicious-rewrite": "{subject} was rewritten without a new version number and was skipped. Someone with "
                          "access to the folder may have altered it.",
    "epoch-mismatch": "{subject} was written with another sync key and is ignored until that device syncs again.",
    "device-mismatch": "{subject} holds data of a different device and was skipped.",
    "unreadable": "{subject} could not be read and was skipped.",
    "folder-missing": "The sync folder is not available. Check that the cloud app is running and the folder "
                      "exists.",
    "folder-unreadable": "The sync folder could not be read. Check that the cloud app is running.",
    "write-failed": "This PC could not write its sync file. Check that the folder is available and not "
                    "read-only.",
    "too-large": "The sync data is over the sync limit (20,000 items or 64 MB). Some changes were not sent.",
    "counter-resynced": "This vault was restored from an older copy; sync caught up automatically.",
    "implausible-counter": "{subject} carried an impossible version number and was skipped. Someone with access "
                           "to the sync folder may have altered it.",
    "view-unsigned": "{subject} is not signed by its device and was skipped. If this keeps happening, someone with "
                     "access to the sync folder may have altered it.",
    "view-forged": "{subject} is signed with the wrong key and was skipped. Someone with access to the sync folder "
                   "may have altered it.",
    "signer-changed": "{subject} has a different signing key in the sync folder's member list than before. If you "
                      "did not set that device up again, remove devices you do not trust.",
    "own-file-rewritten":"This PC's sync file was changed by another device or person. This PC wrote it again. If "
                          "you did not just restore an older backup, remove devices you do not trust.",
    "counter-exhausted": "This PC's sync file cannot be updated any more. Leave sync on this PC and join again.",
    # merging
    "trash-full": "Sync could not move deleted items to the trash because the trash is full. Empty the trash, "
                  "then sync again.",
    "history-quota": "Sync could not keep item history because the history limit was reached. Clear old "
                     "history, then sync again.",
    "bad-peer-data": "Data from {subject} could not be read and was skipped.",
    "bad-peer-record": "One item from {subject} could not be read on this PC and was skipped; everything else "
                       "synced. Updating LocalGateKeys on this PC usually fixes this.",
    "implausible-vv": "One item from {subject} carried an impossible version number and was skipped; everything "
                      "else synced. Someone with access to the sync folder may have altered it.",
    "update-needed": "One item needs a newer LocalGateKeys on this PC. Update LocalGateKeys; that item waits "
                     "until then.",
    "busy": "Items changed while syncing; sync tries again shortly.",
    "apply-failed": "Changes from your other devices could not be saved. Sync tries again later.",
    "local-data": "Some items on this PC could not be read for sync.",
    "error": "Sync hit an unexpected problem. Details are in the error log.",
    # Wi-Fi
    "epoch-behind": "This PC has an older sync key than {subject}. Leave sync on this PC, then pair it again.",
    "peer-epoch-behind": "{subject} has an older sync key. Pair it again with Show QR code.",
    "offer-used-or-expired": "This pairing code was used up or expired. Show a new code.",
    "too-many-peers": "The other device already has the most paired devices. Remove one there first.",
    "peer-update-needed": "{subject} runs an older LocalGateKeys and cannot sync over Wi-Fi with this PC. Update "
                          "LocalGateKeys on that device.",
    "lan-update-needed": "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this PC.",
    "lan-not-listening": "Wi-Fi sync is not listening yet.",
    "listen-failed": "Wi-Fi sync could not start listening. Check the address and port, and that no other app "
                     "uses that port.",
    "no-endpoint": "{subject} has no network address; it connects to this PC instead.",
    "unreachable": "A device could not be reached on this network. Check that it is on the same Wi-Fi and that "
                   "LocalGateKeys is unlocked there.",
    "unknown-peer": "A device that is not paired tried to sync and was refused.",
    "peer-revoked": "{subject} was removed from sync and was not contacted.",
    "peer-mismatch": "{subject} did not match its pairing and was not synced.",
    "group-mismatch": "{subject} belongs to a different sync group.",
    "peer-not-joined": "The other device is not set up for sync.",
    "peer-rejoin-required": "The other device must join sync again on that device.",
    "peer-refused": "The other device refused to sync.",
    "bad-reply": "Another device sent a reply this PC could not understand.",
    "bad-chunk": "Another device sent data this PC could not understand.",
    "bad-message": "Another device sent data this PC could not understand.",
    "refused": "The other device refused the pairing.",
    "bad-offer": "That is not a valid LocalGateKeys pairing code.",
    "already-joined": "This vault is already in a sync group. Leave sync first.",
}


#: ``epoch-behind`` for a vault in a cloud-folder group: the folder brings the new key (no Leave).
_EPOCH_BEHIND_FOLDER_COPY = ("This PC has an older sync key than {subject}. Let the cloud folder finish syncing, "
                             "or join the folder again with the newest sync password.")


_INSTALL_MISMATCH_COPY = "This vault was set up for sync on another PC. Join the folder again on this PC, or reset sync."


_SELF_DROPPED_COPY = "This PC was dropped from the member list. Join the folder again."


_GENERIC_COPY = "Sync reported a problem. Details are in the error log."


_DEVICE_SUFFIX = ".lgksync"


#: Kinds whose detail starts with a file name (``"<file>: reason"``) or is one.
_FILE_KINDS = frozenset({"corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch",
                         "unreadable", "stale-device", "implausible-counter", "view-unsigned", "view-forged"})


#: Kinds whose detail starts with a device id.
_DEVICE_KINDS = frozenset({"member-dropped", "member-added", "bad-name", "bad-peer-data", "bad-peer-record",
                           "implausible-vv", "epoch-behind",
                           "peer-epoch-behind", "no-endpoint", "peer-revoked", "peer-mismatch",
                           "group-mismatch", "peer-update-needed", "signer-changed"})


#: Issues that stop sync for good until the user acts; the banner offers "Reset sync on this PC".
RESET_KINDS = frozenset({"folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt",
                         "keyring-corrupt", "tampered", "identity-mismatch", "keyring-rollback"})


_ERROR_KINDS = RESET_KINDS | frozenset({
    "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable",
    "write-failed", "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
    "counter-exhausted",
})


_NOTICE_KINDS = frozenset({"counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self",
                           "unreachable", "no-endpoint", "lan-not-listening", "not-joined"})


#: Banner order: lower first.
_PRIORITY = (
    "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
    "tampered", "keyring-rollback", "keyring-corrupt", "identity-mismatch", "keyring-missing", "keyring-unreadable", "folder-missing",
    "folder-unreadable", "epoch-behind", "listen-failed", "write-failed", "too-large", "trash-full",
    "history-quota", "member-dropped", "member-added", "old-key-known", "own-file-rewritten", "view-forged",
    "view-unsigned", "rollback", "suspicious-rewrite", "implausible-counter", "corrupt", "bad-peer-data",
    "bad-peer-record", "implausible-vv", "update-needed",
)


def issue_severity(kind: str) -> str:
    """``error`` (sync stopped or cannot write), ``warning`` (something skipped) or ``notice``."""
    if kind in _ERROR_KINDS:
        return "error"
    if kind in _NOTICE_KINDS:
        return "notice"
    return "warning"


def _rank(kind: str) -> tuple[int, int]:
    severity = {"error": 0, "warning": 1, "notice": 2}[issue_severity(kind)]
    return severity, _PRIORITY.index(kind) if kind in _PRIORITY else len(_PRIORITY)


def _subject(kind: str, detail: str, names: Mapping[str, str], own_id: str | None) -> str:
    head = detail.split(": ", 1)[0].strip() if detail else ""
    if kind in ("bad-peer-record", "implausible-vv"):
        head = detail.split(":", 1)[0].strip()  # "<device_id>:<item_id>"
    if kind == "device-mismatch" and not head.endswith(_DEVICE_SUFFIX):
        kind = "bad-peer-data"  # LAN: the detail names a peer device, not a file
    if kind in _DEVICE_KINDS:
        if not head:
            return "Another device"
        if own_id is not None and head == own_id:
            return "this PC"
        name = names.get(head) if kind != "bad-name" else None  # its name is the unreadable part
        return sanitize_name(name) if name else short_id(head)
    if kind in _FILE_KINDS:
        return f"The file {sanitize_name(head, limit=60)}" if head else "A sync file"
    if kind == "ignored-file":
        return sanitize_name(detail, limit=120) if detail else "some files"
    return ""


def effective_kind(kind: str, detail: str) -> str:
    """The kind the screen shows: a ``rollback`` of the key file (not a device file) is ``keyring-rollback``."""
    if kind == "rollback" and not (detail or "").split(": ", 1)[0].strip().endswith(_DEVICE_SUFFIX):
        return "keyring-rollback"
    return kind


def issue_text(issue: Any, *, names: Mapping[str, str] | None = None, own_id: str | None = None,
               folder: bool = False) -> str:
    """User copy for one ``SyncIssue`` (``kind`` + ``detail``).

    *folder*: this vault syncs through a cloud folder (``folder_path`` set),
    which changes the ``epoch-behind`` advice.
    """
    detail = str(getattr(issue, "detail", "") or "")
    kind = effective_kind(str(getattr(issue, "kind", "")), detail)
    if kind == "rejoin-required" and detail == "install-mismatch":
        return _INSTALL_MISMATCH_COPY
    if kind == "member-dropped" and own_id is not None and detail == own_id:
        return _SELF_DROPPED_COPY
    template = _EPOCH_BEHIND_FOLDER_COPY if kind == "epoch-behind" and folder else ISSUE_COPY.get(kind)
    if template is None:
        return _GENERIC_COPY
    subject = _subject(kind, detail, names or {}, own_id)
    if kind == "device-mismatch" and not detail.split(": ", 1)[0].strip().endswith(_DEVICE_SUFFIX):
        template = "{subject} sent data signed for a different device; it was skipped."
    text = template.replace("{subject}", subject)
    return text[0].upper() + text[1:] if text else text


@dataclass(frozen=True)
class IssueView:
    kind: str
    severity: str
    text: str
    reset_offered: bool = False


def _issue_views(issues: Iterable[Any], names: Mapping[str, str], own_id: str | None, *,
                 folder: bool = False) -> tuple[IssueView, ...]:
    """Deduplicated (kind + detail, then identical text) and sorted by importance."""
    seen: set[tuple[str, str]] = set()
    texts: set[str] = set()
    out: list[IssueView] = []
    for issue in issues:
        detail = str(getattr(issue, "detail", "") or "")
        kind = effective_kind(str(getattr(issue, "kind", "")), detail)
        key = (kind, detail)
        if key in seen:
            continue
        seen.add(key)
        text = issue_text(issue, names=names, own_id=own_id, folder=folder)
        if text in texts:
            continue
        texts.add(text)
        out.append(IssueView(kind, issue_severity(kind), text, kind in RESET_KINDS))
    out.sort(key=lambda view: _rank(view.kind))
    return tuple(out)


ERROR_COPY: Mapping[str, str] = {
    "password": "That sync password is not right for this folder.",
    "password-reused": "Choose a new sync password; it must differ from the current one.",
    "weak-password": "The sync password needs at least 12 characters and a Strong rating.",
    "folder-in-use": "This folder already holds a sync group. Use Join a folder instead.",
    "no-group": "There is no sync group in this folder yet. Create one, or choose the folder your other device "
                "uses.",
    "different-group": "This vault already syncs with another group. Leave sync first.",
    "keyring-changed": "Another device changed the sync folder at the same moment. Try again.",
    "folder-error": "The folder could not be used. Check that it exists and is writable.",
    "folder-missing": "That folder does not exist or is not available.",
    "too-many-members": "This sync group already has the most devices (16). Remove one first.",
    "cannot-remove-self": "This PC cannot remove itself. Use Leave sync instead.",
    "already-joined": "This vault is already in a sync group. Leave sync first.",
    "not-joined": "This vault is not in a sync group.",
    "rejoin-required": "This vault was set up for sync on another PC. Join the folder again on this PC.",
    "not-member": "That device is not in this sync group.",
    "missed-rotation": "This PC missed a password change. Join the folder again with the current sync password.",
    "offer-used-or-expired": "This pairing code was used up or expired. Show a new code.",
    "unreachable": "The other device could not be reached. Check that both are on the same Wi-Fi and that the "
                   "other device shows its code.",
    "too-many-peers": "The other device already has the most paired devices. Remove one there first.",
    "declined": "The other device declined, or nobody chose Accept there in time. Show a new code there and "
                "choose Accept when both screens show the same code.",
    "update-needed": "Update LocalGateKeys on this PC to pair with that device.",
    "bad-offer": "That is not a valid LocalGateKeys pairing code.",
    "refused": "The other device refused the pairing. Show a new code and try again.",
    "not-our-offer": "This pairing code belongs to another sync group. Show a new code.",
    "already-has-folder": "This sync group already uses a cloud folder.",
    "folder-has-other-group": "That folder holds a different sync group. Choose another folder, or the folder "
                              "your other device added to this group.",
    "different-group-key": "That folder's sync group does not match this vault's group. Choose the folder your "
                           "other device added to this group.",
    "epoch-mismatch": "The sync key in that folder changed after this PC was paired. Leave sync on this PC, then "
                      "use Join a folder with the current sync password.",
    "already-member": "This PC is already in that folder's sync group.",
    "lan-peer-removed": "A Wi-Fi device was removed from this group and still knows its sync key, so the cloud "
                        "folder needs a new key. Choose Add a cloud folder to this group again and confirm.",
}


def error_text(exc: BaseException) -> str:
    """User copy for a refused sync action (``FolderSyncError``/``LanSyncError``/``KeyringError`` reason)."""
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str):
        if reason in ERROR_COPY:
            return ERROR_COPY[reason]
        if reason in ISSUE_COPY:
            return issue_text(type("Issue", (), {"kind": reason, "detail": ""})())
        return "Sync could not finish that step. Details are in the error log."
    from ..session_guard import StaleSession

    if isinstance(exc, StaleSession) or type(exc).__name__ == "SyncAborted":
        return "The vault locked or sync stopped before this finished. Unlock and try again."
    return "Sync could not finish that step. Details are in the error log."


@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    score: int
    label: str
    message: str


def check_sync_password(password: str, confirm_password: str) -> PasswordCheck:
    """The sync-password gate: 12+ characters, score >= 3 ("Strong"), both entries equal."""
    password = password or ""
    score = estimate_strength(password).score if password else 0
    label = STRENGTH_LABELS[max(0, min(score, len(STRENGTH_LABELS) - 1))]
    if len(password) < MIN_SYNC_PASSWORD_LEN:
        return PasswordCheck(False, score, label, f"Use at least {MIN_SYNC_PASSWORD_LEN} characters.")
    if score < MIN_SYNC_PASSWORD_SCORE:
        return PasswordCheck(False, score, label, "Too easy to guess. Add more words or characters.")
    if password != (confirm_password or ""):
        return PasswordCheck(False, score, label, "The two passwords do not match.")
    return PasswordCheck(True, score, label, "Good.")


def _usable_lan_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (address.is_unspecified or address.is_multicast or address.is_reserved or address.is_loopback):
        return False
    return is_lan_address(address)


def validate_lan_endpoint(text: str) -> tuple[str | None, str]:
    """``(normalised "host:port", "")`` for a private/link-local endpoint, else ``(None, message)``.

    IPv6 addresses go in brackets (``[fe80::1]:47821``).  Ports below 1024 are refused.
    """
    raw = (text or "").strip()
    if not raw:
        return None, "Enter this PC's address and port, for example 192.168.1.20:47821."
    host, sep, port_text = raw.rpartition(":")
    if not sep or not host:
        return None, "Use address:port, for example 192.168.1.20:47821."
    bracketed = host.startswith("[") and host.endswith("]")
    if bracketed:
        host = host[1:-1]
    elif ":" in host:
        return None, "Put an IPv6 address in brackets, for example [fe80::1]:47821."
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None, "Use this PC's numeric address (like 192.168.1.20), not a name."
    if bracketed != (address.version == 6):
        return None, "Use address:port, for example 192.168.1.20:47821."
    if not _usable_lan_address(address):
        return None, "Use this PC's address on your home network (a private or link-local address)."
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        return None, "Use a port between 1024 and 65535."
    shown = f"[{address}]" if address.version == 6 else str(address)
    return f"{shown}:{int(port_text)}", ""


def suggest_lan_endpoint(addresses: Iterable[str], port: int = DEFAULT_LAN_PORT) -> str | None:
    """The first private IPv4 address (link-local last) of this PC with the fixed port, or None."""
    private: list[str] = []
    link_local: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if address.version != 4 or not _usable_lan_address(address):
            continue
        (link_local if address.is_link_local else private).append(str(address))
    chosen = (private or link_local or [None])[0]
    return None if chosen is None else f"{chosen}:{port}"


def local_ipv4_addresses() -> list[str]:
    """This PC's IPv4 addresses from local name resolution (no packets are sent)."""
    import socket

    found: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if address not in found:
                found.append(address)
    except OSError:
        pass
    return found


def countdown_text(seconds_left: float) -> str:
    left = int(-(-max(0.0, seconds_left) // 1))  # ceil
    if left <= 0:
        return "Expired"
    return f"Expires in {left // 60}:{left % 60:02d}"


def ago_text(timestamp: int | None, now: float) -> str:
    if timestamp is None:
        return "Not synced yet"
    age = max(0, int(now) - int(timestamp))
    if age < 60:
        return "Last synced just now"
    if age < 3600:
        return f"Last synced {age // 60} min ago"
    if age < 86400:
        return f"Last synced {age // 3600} h ago"
    return f"Last synced {age // 86400} d ago"


@dataclass(frozen=True)
class MemberSnapshot:
    """A keyring member; ``file_written_at`` is its device file's header time (None: no file)."""

    device_id: str
    name: str
    is_self: bool = False
    file_written_at: int | None = None


@dataclass(frozen=True)
class PeerSnapshot:
    """A paired Wi-Fi peer; ``endpoint`` None means it connects to this PC (a phone)."""

    device_id: str
    endpoint: str | None = None


@dataclass(frozen=True)
class GroupSnapshot:
    """What the screen needs from the stored ``SyncGroupState`` (read by a worker job)."""

    device_id: str
    folder_path: str | None
    epoch: int
    install_ok: bool
    members: tuple[MemberSnapshot, ...] = ()
    lan_peers: tuple[PeerSnapshot, ...] = ()
    item_names: Mapping[str, str] = field(default_factory=dict)
    #: Keyring members added by another device and not confirmed yet (``member-added``).
    unacked: tuple[str, ...] = ()
    #: A Wi-Fi peer was removed since the key last changed (``SyncGroupState.lan_removed``).
    lan_removed: bool = False

    def names(self) -> dict[str, str]:
        return {m.device_id: m.name for m in self.members}


@dataclass(frozen=True)
class MemberView:
    device_id: str
    name: str
    detail: str = ""
    is_self: bool = False
    removable: bool = False
    orphan: str | None = None  # "no-file" or "stale"


@dataclass(frozen=True)
class CardView:
    key: str
    title: str
    state: str
    state_text: str
    members: tuple[MemberView, ...] = ()
    last_sync_text: str = ""
    actions: frozenset[str] = frozenset()
    banner: IssueView | None = None
    issues: tuple[IssueView, ...] = ()
    hint: str = ""


@dataclass(frozen=True)
class SyncScreenView:
    wifi: CardView
    folder: CardView
    banner: IssueView | None = None
    skipped: tuple[str, ...] = ()
    running: bool = False
    conflicts: int = 0
    conflicts_text: str = ""


def orphan_members(group: GroupSnapshot | None, *, now: float) -> tuple[MemberView, ...]:
    """Members (not this PC) without a device file, or whose file is over a year old."""
    if group is None:
        return ()
    out: list[MemberView] = []
    for member in group.members:
        if member.is_self:
            continue
        if member.file_written_at is None:
            orphan, detail = "no-file", "Has no sync file in the folder"
        elif member.file_written_at < now - STALE_AFTER_SECONDS:
            orphan, detail = "stale", "Has not synced for over a year"
        else:
            continue
        out.append(MemberView(member.device_id, sanitize_name(member.name), detail, False, True, orphan))
    return tuple(out)


def _transport(status: Any, name: str) -> Any:
    for transport in getattr(status, "transports", ()) or ():
        if getattr(transport, "name", None) == name:
            return transport
    return None


def _global_issues(status: Any) -> list[Any]:
    """Issues not raised by either transport (install binding, damaged state)."""
    if status is None:
        return []
    per_transport = {(i.kind, i.detail) for t in status.transports for i in t.issues}
    return [i for i in status.issues if (i.kind, i.detail) not in per_transport]


def _conflicts_text(count: int) -> str:
    if count <= 0:
        return ""
    noun = "copy" if count == 1 else "copies"
    return f"{count} conflict {noun} made since unlock: look for items marked as conflict copies"


def _folder_card(status: Any, group: GroupSnapshot | None, *, now: float, available: bool,
                 state_corrupt: bool, names: Mapping[str, str], own: str | None) -> CardView:
    title = "Cloud folder"
    transport = _transport(status, "folder")
    issues = _issue_views(getattr(transport, "issues", ()) or (), names, own)
    banner = issues[0] if issues else None
    running = bool(getattr(status, "running", False))
    last = ago_text(getattr(transport, "last_sync", None), now)
    if not available:
        return CardView("folder", title, "unavailable", "Sync runs while the vault is unlocked on this PC.")
    if state_corrupt:
        return CardView("folder", title, "broken", "Sync settings on this PC are damaged.",
                        actions=frozenset({"reset"}))
    if group is None:
        return CardView("folder", title, "off",
                        "Off. Keep your devices in step through a folder your cloud app already syncs "
                        "(OneDrive, Dropbox, iCloud Drive). Everything in it is encrypted.",
                        actions=frozenset({"create-group", "join-folder"}))
    unacked = set(group.unacked)
    members = tuple(
        MemberView(m.device_id, sanitize_name(m.name),
                   "This PC" if m.is_self else ("Added by another device, not confirmed"
                                                if m.device_id in unacked else ""),
                   m.is_self, not m.is_self)
        for m in group.members)
    if not group.folder_path:
        if not group.install_ok:
            return CardView("folder", title, "lan-only", "Not used: this vault syncs over Wi-Fi only.")
        return CardView("folder", title, "lan-only", "Not used: this vault syncs over Wi-Fi only.",
                        actions=frozenset({"add-folder", "use-folder"}), hint=LAN_ONLY_FOLDER_HINT)
    folder_text = f"Folder: {sanitize_name(group.folder_path, limit=80)}"
    common = dict(members=members, last_sync_text=last, banner=banner, issues=issues)
    if not group.install_ok:
        return CardView("folder", title, "rejoin", f"Needs to join again on this PC. {folder_text}",
                        actions=frozenset({"join-folder", "leave", "reset"}), **common)
    kinds = {issue.kind for issue in issues}
    if "folder-has-other-group" in kinds:
        actions = {"leave", "reset", "sync-now"}
        state, text = "stopped", "Stopped: the folder holds another sync group."
    elif kinds & {"rotation-conflict", "removed-or-conflict", "rejoin-required"}:
        actions = {"join-folder", "leave", "reset", "sync-now"}
        state, text = "stopped", "Stopped: join the folder again."
    elif kinds & (RESET_KINDS - {"state-corrupt"}):
        actions = {"join-folder", "leave", "reset", "sync-now"}
        state, text = "stopped", "Stopped: the sync folder needs attention."
    else:
        actions = {"sync-now", "change-password", "remove-device", "leave"}
        if orphan_members(group, now=now):
            actions.add("show-orphans")
        if unacked & {m.device_id for m in group.members}:
            actions.add("ack-members")
        state, text = "on", "On."
    if running:
        actions.discard("sync-now")
        text = f"{text} Syncing now…"
    return CardView("folder", title, state, f"{text} {folder_text}", actions=frozenset(actions), **common)


def _wifi_card(status: Any, group: GroupSnapshot | None, *, now: float, available: bool, endpoint: str,
               state_corrupt: bool, names: Mapping[str, str], own: str | None) -> CardView:
    title = "Wi-Fi (this network)"
    transport = _transport(status, "lan")
    in_folder = group is not None and bool(group.folder_path)
    issues = _issue_views(getattr(transport, "issues", ()) or (), names, own, folder=in_folder)
    banner = issues[0] if issues else None
    running = bool(getattr(status, "running", False))
    if not available:
        return CardView("wifi", title, "unavailable", "Sync runs while the vault is unlocked on this PC.")
    if state_corrupt:
        return CardView("wifi", title, "broken", "Sync settings on this PC are damaged.")
    peers: tuple[MemberView, ...] = ()
    if group is not None:
        peers = tuple(
            MemberView(p.device_id, sanitize_name(names.get(p.device_id) or short_id(p.device_id)),
                       f"At {sanitize_name(p.endpoint, limit=48)}" if p.endpoint else "Connects to this PC",
                       False, True)
            for p in group.lan_peers)
    lan_only = group is not None and not group.folder_path
    if not endpoint:
        actions = {"wifi-enable"} | ({"join-qr"} if group is None else set())
        if lan_only:
            actions.add("leave")
        return CardView("wifi", title, "off",
                        "Off. Sync with your phone or another PC on the same network, without any cloud.",
                        members=peers, actions=frozenset(actions), banner=banner, issues=issues)
    where = f"This PC listens on {endpoint}."
    if group is None:
        return CardView("wifi", title, "ready", f"Ready. {where} Show a QR code to pair your first device.",
                        actions=frozenset({"show-qr", "join-qr", "wifi-disable"}), banner=banner, issues=issues)
    common = dict(members=peers, last_sync_text=ago_text(getattr(transport, "last_sync", None), now),
                  banner=banner, issues=issues)
    if not group.install_ok:
        return CardView("wifi", title, "rejoin", "Needs to be set up again on this PC.",
                        actions=frozenset({"leave", "reset", "wifi-disable"}), **common)
    actions = {"show-qr", "sync-now", "wifi-disable"}
    if peers:
        actions.add("remove-device")
    if lan_only:
        # Includes epoch-behind in a Wi-Fi-only group: its copy says leave, then pair again.  A folder
        # member is told to let the folder sync or join again instead, so Leave is not offered there.
        actions.add("leave")
    text = f"On. {where}"
    if running:
        actions.discard("sync-now")
        text = f"{text} Syncing now…"
    if not peers:
        text = f"{text} No devices paired yet."
    return CardView("wifi", title, "on", text, actions=frozenset(actions), **common)


def sync_view(status: Any, group: GroupSnapshot | None, *, lan_endpoint: str, now: float,
              available: bool = True, state_corrupt: bool = False) -> SyncScreenView:
    """The whole Sync screen for one ``SyncStatusView`` and the stored group (pure)."""
    names = group.names() if group is not None else {}
    own = group.device_id if group is not None else None
    endpoint, _error = validate_lan_endpoint(lan_endpoint) if lan_endpoint else (None, "")
    global_views = _issue_views(_global_issues(status), names, own,
                                folder=group is not None and bool(group.folder_path))
    if state_corrupt and not any(v.kind == "state-corrupt" for v in global_views):
        global_views = (IssueView("state-corrupt", "error", ISSUE_COPY["state-corrupt"], True), *global_views)
    folder = _folder_card(status, group, now=now, available=available, state_corrupt=state_corrupt,
                          names=names, own=own)
    wifi = _wifi_card(status, group, now=now, available=available, endpoint=endpoint or "",
                      state_corrupt=state_corrupt, names=names, own=own)
    return SyncScreenView(wifi=wifi, folder=folder, banner=global_views[0] if global_views else None,
                          skipped=_skipped_lines(getattr(status, "skipped", ()) or (),
                                                 group.item_names if group is not None else {}),
                          running=bool(getattr(status, "running", False)),
                          conflicts=int(getattr(status, "conflicts", 0) or 0),
                          conflicts_text=_conflicts_text(int(getattr(status, "conflicts", 0) or 0)))


def _skipped_lines(skipped: Iterable[tuple[str, str]], item_names: Mapping[str, str]) -> tuple[str, ...]:
    """One line per skipped record (named once), unnamed ones counted together."""
    named: list[str] = []
    unnamed: list[str] = []
    seen: set[str] = set()
    for row in skipped:
        item_id = str(row[0]) if row else ""
        if not item_id or item_id in seen:
            continue
        seen.add(item_id)
        name = item_names.get(item_id)
        if name:
            named.append(f"“{sanitize_name(name)}” could not be synced and stays only on this PC.")
        else:
            unnamed.append(item_id)
    if unnamed:
        noun, verb = ("item", "stays") if len(unnamed) == 1 else ("items", "stay")
        named.append(f"{len(unnamed)} other {noun} could not be synced and {verb} only on this PC.")
    return tuple(named)


@dataclass(frozen=True)
class FolderSetup:
    """Dialog copy and job for one folder action of a Wi-Fi-only group."""

    title: str
    intro: str
    confirm_twice: bool
    busy: str
    done_text: str
    job: Callable[[str, str, str, str], Callable[[Any, Any, Any], Any]]


def folder_setup(action: str) -> FolderSetup | None:
    """``add-folder`` (new sync password, twice) or ``use-folder`` (the folder's password, once); else None."""
    if action == "add-folder":
        return FolderSetup(
            "Add a cloud folder",
            "Choose the folder your cloud app syncs (for example OneDrive), then a NEW sync password. Your paired "
            "devices stay in this group; on each of them choose Use this group's cloud folder with this password.",
            True, "Adding the cloud folder…",
            "The cloud folder was added. On your other devices, choose Use this group's cloud folder.",
            add_folder_job)
    if action == "use-folder":
        return FolderSetup(
            "Use this group's cloud folder",
            "Choose the folder another device in this group added (the folder that contains “LocalGateKeys "
            "Sync”), then enter its sync password. This PC keeps its Wi-Fi pairings.",
            False, "Connecting the cloud folder…", "This PC now also syncs through the cloud folder.",
            attach_folder_job)
    return None


def _read_header_time(path: Any) -> int | None:
    """``written_at`` from a device file's plain header (display only; not authenticated)."""
    import json

    from ..sync.group import MAGIC

    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if not head.startswith(MAGIC):
        return None
    end = head.find(b"\n", len(MAGIC))
    try:
        header = json.loads(head[len(MAGIC):end]) if end > 0 else None
    except ValueError:
        return None
    value = header.get("written_at") if isinstance(header, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def snapshot_job(install_id: str, skipped_ids: Iterable[str] = ()) -> Callable[[Any, Any, Any], Any]:
    """A job returning ``(GroupSnapshot | None, state_corrupt)`` for the screen."""
    wanted = set(skipped_ids)

    def job(session: Any, lease: Any, gate: Any) -> tuple[GroupSnapshot | None, bool]:
        from ..sync.folder_transport import FolderSync, is_safe_device_id
        from ..sync.group import GroupKey
        from ..sync.keyring import KeyringError, member_names, parse_keyring
        from ..sync.vault_bridge import BridgeError, load_sync_state

        try:
            state = load_sync_state(session)
        except BridgeError:
            return None, True
        if state is None:
            return None, False
        item_names: dict[str, str] = {}
        if wanted:
            try:
                for summary in session.item_service.metadata_summaries():
                    if str(summary.id) in wanted:
                        item_names[str(summary.id)] = str(getattr(summary, "title", "") or "")
            except Exception:  # noqa: BLE001 - names are a nicety
                item_names = {}
        ring_members: list[tuple[str, str]] = []
        if state.keyring:
            try:
                # The stored keyring is the last one this device accepted under the stored key.
                ring = parse_keyring(state.keyring)
                names = member_names(ring, GroupKey(state.group_id, state.epoch, state.key))
                ring_members = [(device_id, name if name is not None else UNNAMED_DEVICE)
                                for device_id, name in names.items()]
            except (KeyringError, KeyError, TypeError, ValueError):
                ring_members = []
        times: dict[str, int | None] = {}
        if state.folder_path and ring_members:
            folder = FolderSync(state.folder_path, install_id=install_id)
            with gate.ui_released():  # folder I/O only (a cloud placeholder may stall)
                for device_id, _name in ring_members:
                    if not is_safe_device_id(device_id):
                        times[device_id] = None
                        continue
                    try:
                        times[device_id] = _read_header_time(folder.device_file(device_id))
                    except (OSError, ValueError):
                        times[device_id] = None
        members = tuple(
            MemberSnapshot(device_id, name, device_id == state.device_id, times.get(device_id))
            for device_id, name in ring_members)
        peers: list[PeerSnapshot] = []
        for entry in state.lan_peers:
            device_id = entry.get("device_id")
            if not isinstance(device_id, str) or entry.get("revoked") is True:
                continue
            where = entry.get("endpoint")
            endpoint = None
            if isinstance(where, Mapping) and isinstance(where.get("host"), str):
                host = where["host"]
                endpoint = f"[{host}]:{where.get('port')}" if ":" in host else f"{host}:{where.get('port')}"
            peers.append(PeerSnapshot(device_id, endpoint))
        return GroupSnapshot(state.device_id, state.folder_path, state.epoch, state.install_id == install_id,
                             members, tuple(peers), item_names, unacked=tuple(state.unacked_members),
                             lan_removed=state.lan_removed), False

    return job


def create_group_job(folder: str, password: str, device_name: str, install_id: str):
    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.folder_transport import create_folder_group

        return create_folder_group(folder, session, lease, password, device_name, install_id=install_id,
                                   ui_released=gate.ui_released, run=False)

    return job


def join_folder_job(folder: str, password: str, device_name: str, install_id: str):
    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.folder_transport import join_folder_group

        return join_folder_group(folder, session, lease, password, device_name, install_id=install_id,
                                 ui_released=gate.ui_released, run=False)

    return job


def add_folder_job(folder: str, password: str, device_name: str, install_id: str, fresh_key: bool = False):
    """*fresh_key*: the user confirmed a new key because a Wi-Fi device was removed (audit M9)."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync import folder_transport

        return folder_transport.add_folder_to_group(folder, session, lease, password, device_name,
                                                    install_id=install_id, ui_released=gate.ui_released, run=False,
                                                    fresh_key=fresh_key)

    return job


def attach_folder_job(folder: str, password: str, device_name: str, install_id: str):
    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync import folder_transport

        return folder_transport.attach_folder(folder, session, lease, password, device_name,
                                              install_id=install_id, ui_released=gate.ui_released, run=False)

    return job


def rotate_job(new_password: str, remove: Iterable[str], install_id: str, lan_transport: Callable[[], Any],
               keep: Iterable[str] | None = None):
    """Change the sync password, removing *remove* (keyring members and LAN peers).

    *keep*: the members the user confirmed (``RotationPlan.keep``); only they and this
    PC get the new key (audit M10).
    """
    drop = tuple(remove)
    kept = None if keep is None else tuple(keep)

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.folder_transport import FolderSyncError, rotate_folder_group
        from ..sync.lan_sync import remove_lan_peer
        from ..sync.vault_bridge import load_sync_state

        state = load_sync_state(session)
        if state is None or not state.folder_path:
            raise FolderSyncError("not-joined")
        report = rotate_folder_group(state.folder_path, session, lease, new_password, drop, keep=kept,
                                     install_id=install_id, ui_released=gate.ui_released, run=False)
        transport = lan_transport()
        for device_id in drop:  # revoke on the running listener at once
            remove_lan_peer(session, lease, device_id, install_id=install_id, transport=transport)
        return report

    return job


def remove_lan_peer_job(device_id: str, install_id: str, lan_transport: Callable[[], Any]):
    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.lan_sync import remove_lan_peer

        return remove_lan_peer(session, lease, device_id, install_id=install_id, transport=lan_transport())

    return job


def acknowledge_job(device_ids: Iterable[str], install_id: str):
    """Confirm the ``member-added`` devices the user was shown."""
    ids = tuple(device_ids)

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.folder_transport import acknowledge_members

        return acknowledge_members(session, lease, ids, install_id=install_id)

    return job


def leave_job(install_id: str):
    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.folder_transport import leave_folder_group

        return leave_folder_group(session, lease, install_id=install_id)

    return job


def begin_pairing_job(host: str, port: int, install_id: str):
    """Create a Wi-Fi group if there is none yet, then the pairing offer to show as a QR code."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.lan_sync import begin_pairing, create_lan_group
        from ..sync.vault_bridge import load_sync_state

        if load_sync_state(session) is None:
            create_lan_group(session, lease, install_id=install_id)
        return begin_pairing(session, lease, host, port, install_id=install_id)

    return job


class _ReleasingEnroll:
    """``SyncTransport`` for ``enroll_from_qr``: the network round trip releases the gate and the UI."""

    def __init__(self, inner: Any, gate: Any) -> None:
        self._inner, self._gate = inner, gate

    def enroll(self, *args: Any, **kwargs: Any) -> Any:
        with self._gate.released():
            return self._inner.enroll(*args, **kwargs)


def enroll_job(qr_text: str, install_id: str, endpoint: Any, *, on_code: Any = None):
    """Join by QR text; *on_code* receives the verification code the inviting device shows next to Accept."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.lan_sync import enroll_from_qr
        from ..sync.transport import SyncTransport

        return enroll_from_qr(qr_text, session, lease, install_id=install_id, endpoint=endpoint,
                              transport=_ReleasingEnroll(SyncTransport(), gate), on_code=on_code)

    return job


def _noop_job(session: Any, lease: Any, gate: Any) -> None:
    """Lets ``submit`` re-read the state (listener start/stop after a settings change)."""
    return None


_ACTION_LABELS = {
    "sync-now": "Sync now",
    "create-group": "Create sync group…",
    "join-folder": "Join a folder…",
    "add-folder": "Add a cloud folder to this group…",
    "use-folder": "Use this group's cloud folder…",
    "change-password": "Change sync password…",
    "remove-device": "Remove a device…",
    "show-orphans": "Unused members…",
    "ack-members": "These are my devices",
    "leave": "Leave sync…",
    "reset": "Reset sync on this PC…",
    "show-qr": "Show QR code…",
    "join-qr": "Join by QR text…",
    "wifi-enable": "Turn on Wi-Fi sync…",
    "wifi-disable": "Turn off Wi-Fi sync",
}


_ACTION_ORDER = ("sync-now", "show-qr", "join-qr", "create-group", "join-folder", "add-folder", "use-folder",
                 "ack-members", "change-password", "remove-device", "show-orphans", "wifi-enable", "wifi-disable", "leave", "reset")


_PRIMARY = frozenset({"sync-now", "create-group", "add-folder", "show-qr", "wifi-enable"})
