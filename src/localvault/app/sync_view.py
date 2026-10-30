"""Sync screen view-models, wording and background jobs (no UI toolkit)."""
from __future__ import annotations

import ipaddress
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..password_tools import estimate_strength, strength_label
from ..sync.keyring import UNNAMED_DEVICE
from ..sync.lan_address import is_lan_address
from ..i18n import t

#: Fixed port suggested for this PC's Wi-Fi sync listener.
DEFAULT_LAN_PORT = 47821


#: Longest device or item name shown on the screen (characters, including the ellipsis).
NAME_LIMIT = 40


#: Sync password rules (``sync/keyring.py``): length and ``estimate_strength`` score.
MIN_SYNC_PASSWORD_LEN = 12


MIN_SYNC_PASSWORD_SCORE = 3


#: Peer files older than this are stale (``folder_transport.STALE_AFTER_SECONDS``).
STALE_AFTER_SECONDS = 365 * 86400


PASSWORD_ADVICE = "sync.writeThisPasswordDownNever"  # noqa: S105 - user copy


LEAVE_TEXT = (
    "sync.leaveSyncOnThisPc"
)


LEAVE_WIFI_TEXT = (
    "sync.leaveSyncOnThisPc2"
)


#: "Copy code text" is cleared from the clipboard after this long (if it still holds the code).
QR_CLIPBOARD_SECONDS = 120


RESET_TEXT_1 = (
    "sync.resetSyncOnThisPc"
)


RESET_TEXT_2 = "sync.areYouSureThisCannot"


LAN_ONLY_FOLDER_HINT = (
    "sync.toSyncThroughACloud"
)


def leave_text(group: Any) -> str:
    """Leave confirmation: the cloud-folder text, or the Wi-Fi-only text for a group without a folder."""
    return t(LEAVE_TEXT if getattr(group, "folder_path", None) else LEAVE_WIFI_TEXT)


def remove_wifi_device_text(name: str) -> str:
    """Confirmation for removing a Wi-Fi-only paired device (no sync password to change)."""
    return t("sync.removeWifiDevice", name=name)


def reset_result_text(cleared: bool | None) -> str:
    if cleared is None:
        return t("sync.syncCouldNotBeReset")
    return t("sync.syncWasResetOnThis") if cleared else t("sync.thereWasNothingToReset")


def should_clear_clipboard(current: Any, payload: str) -> bool:
    """Clear the copied pairing code only if the clipboard still holds exactly that text."""
    return isinstance(current, str) and current == payload


def rotation_intro(group: Any, *, removing: str | None = None) -> str:
    """Copy for a password change (rotation), naming QR-paired devices that must pair again."""
    text = (t("sync.enterANewSyncPassword"))
    peers = [p for p in getattr(group, "lan_peers", ()) or () if p.device_id != removing]
    if peers:
        names = group.names() if hasattr(group, "names") else {}
        shown = ", ".join(sanitize_name(names.get(p.device_id) or short_id(p.device_id)) for p in peers)
        text += t("sync.qrPairedMustRepair", shown=shown)
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
    shown = [_member_name(group, d) for d in keep] + [t("sync.thisPc")]
    text = t("sync.newKeyGoesOnlyTo", shown=", ".join(shown))
    lose = [_member_name(group, m.device_id) for m in members
            if m.device_id in unacked and m.device_id not in gone and not m.is_self]
    if lose:
        text += t("sync.notConfirmedLoseAccess", shown=", ".join(lose))
    return RotationPlan(keep, text)


def lan_removed_folder_text(group: Any) -> str:
    """Confirmation for adding a cloud folder after a Wi-Fi device was removed (audit M9)."""
    peers = [p.device_id for p in getattr(group, "lan_peers", ()) or ()]
    text = (t("sync.aWiFiDeviceWas"))
    if peers:
        shown = ", ".join(_member_name(group, d) for d in peers)
        text += t("sync.lanPeersCannotRekey", shown=shown)
    return text + "\n\n" + t("common.continueQuestion")


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
    return t("sync.deviceShortId", id=sanitize_name(device_id, limit=9)[:8])


#: User copy per issue kind; ``{subject}`` is the file or device the issue is about.
ISSUE_COPY: Mapping[str, str] = {
    # keyring and membership (cloud folder)
    "keyring-restored": "sync.theSyncFolderHadAn",
    "folder-has-other-group": "sync.thisSyncFolderNowHolds",
    "rotation-conflict": "sync.twoDevicesChangedTheSync",
    "removed-or-conflict": "sync.thisDeviceMayHaveBeen",
    "rejoin-required": "sync.thisPcMustJoinSync",
    "member-dropped": "sync.disappearedFromTheMemberList",
    "member-added": "sync.wasAddedToThisSync",
    "old-key-known": "sync.aWiFiDeviceRemoved",
    "tampered": "sync.theKeyFileInThe",
    "keyring-corrupt": "sync.theKeyFileInThe2",
    "keyring-missing": "sync.theKeyFileInThe3",
    "keyring-unreadable": "sync.theKeyFileInThe4",
    "unsafe-member": "sync.aDeviceInTheMember",
    "bad-name": "sync.theNameOfInThe",
    "state-corrupt": "sync.thisVaultSSyncSettings",
    "identity-mismatch": "sync.thisPcSSyncIdentity",
    "not-joined": "syncStatusPage.off",
    # device files
    "stale-self": "sync.thisPcHadNotSynced",
    "stale-device": "sync.hasNotSyncedForOver",
    "ignored-file": "sync.unknownFilesInTheSync",
    "corrupt": "sync.isDamagedOrCouldNot",
    "keyring-rollback": "sync.theKeyFileInThe5",
    "rollback": "sync.wasReplacedByAnOlder",
    "suspicious-rewrite": "sync.wasRewrittenWithoutANew",
    "epoch-mismatch": "sync.wasWrittenWithAnotherSync",
    "device-mismatch": "sync.holdsDataOfADifferent",
    "unreadable": "sync.couldNotBeReadAnd",
    "folder-missing": "sync.theSyncFolderIsNot",
    "folder-unreadable": "sync.theSyncFolderCouldNot",
    "write-failed": "sync.thisPcCouldNotWrite",
    "too-large": "sync.theSyncDataIsOver",
    "counter-resynced": "sync.thisVaultWasRestoredFrom",
    "implausible-counter": "sync.carriedAnImpossibleVersionNumber",
    "view-unsigned": "sync.isNotSignedByIts",
    "view-forged": "sync.isSignedWithTheWrong",
    "signer-changed": "sync.hasADifferentSigningKey",
    "own-file-rewritten":"sync.thisPcSSyncFile",
    "counter-exhausted": "sync.thisPcSSyncFile2",
    # merging
    "trash-full": "sync.syncCouldNotMoveDeleted",
    "history-quota": "sync.syncCouldNotKeepItem",
    "bad-peer-data": "sync.dataFromCouldNotBe",
    "bad-peer-record": "sync.oneItemFromCouldNot",
    "implausible-vv": "sync.oneItemFromCarriedAn",
    "update-needed": "sync.oneItemNeedsANewer",
    "busy": "sync.itemsChangedWhileSyncingSync",
    "apply-failed": "sync.changesFromYourOtherDevices",
    "local-data": "sync.someItemsOnThisPc",
    "error": "sync.syncHitAnUnexpectedProblem",
    # Wi-Fi
    "epoch-behind": "sync.thisPcHasAnOlder",
    "peer-epoch-behind": "sync.hasAnOlderSyncKey",
    "offer-used-or-expired": "sync.thisPairingCodeWasUsed",
    "too-many-peers": "sync.theOtherDeviceAlreadyHas",
    "peer-update-needed": "sync.runsAnOlderLocalgatekeysAnd",
    "lan-update-needed": "sync.anotherDeviceRunsANewer",
    "lan-not-listening": "sync.wiFiSyncIsNot",
    "listen-failed": "sync.wiFiSyncCouldNot",
    "no-endpoint": "sync.hasNoNetworkAddressIt",
    "unreachable": "sync.aDeviceCouldNotBe",
    "unknown-peer": "sync.aDeviceThatIsNot",
    "peer-revoked": "sync.wasRemovedFromSyncAnd",
    "peer-mismatch": "sync.didNotMatchItsPairing",
    "group-mismatch": "sync.belongsToADifferentSync",
    "peer-not-joined": "sync.theOtherDeviceIsNot",
    "peer-rejoin-required": "sync.theOtherDeviceMustJoin",
    "peer-refused": "sync.theOtherDeviceRefusedTo",
    "bad-reply": "sync.anotherDeviceSentAReply",
    "bad-chunk": "sync.anotherDeviceSentDataThis",
    "bad-message": "sync.anotherDeviceSentDataThis",
    "refused": "sync.theOtherDeviceRefusedThe",
    "bad-offer": "sync.thatIsNotAValid",
    "already-joined": "sync.thisVaultIsAlreadyIn",
    # rollback witnesses (plan Part B, Task B4)
    "vault-rollback": "sync.anotherDeviceInYourSync",
    "peer-vault-rollback": "sync.isNowUsingAnOlder",
    "witness-implausible": "sync.reportedAnImpossibleVersionNumber",
    "rollback-acknowledged": "sync.youRestoredAnOlderBackup",
    "attachment-missing": "sync.aFileAttachedOnAnother",
    "attachment-refused": "sync.aFileFromAnotherDevice",
}


#: Title of the ``vault-rollback`` banner and the label of its acknowledge button (Task B4 copy).
ROLLBACK_TITLE = "sync.thisVaultIsOlderThan"
ROLLBACK_ACTION = "sync.thisWasMeKeepThis"
ROLLBACK_CONFIRM_TITLE = "sync.keepThisCopyOfThe"
ROLLBACK_CONFIRM_TEXT = ("sync.chooseThisOnlyIfYou")
PEER_ROLLBACK_DISMISS = "toast.dismiss"

#: Shown in their own banner (with buttons), not in the transport cards.
ROLLBACK_KINDS = frozenset({"vault-rollback", "peer-vault-rollback"})


#: ``epoch-behind`` for a vault in a cloud-folder group: the folder brings the new key (no Leave).
_EPOCH_BEHIND_FOLDER_COPY = ("sync.thisPcHasAnOlder2")


_INSTALL_MISMATCH_COPY = "sync.thisVaultWasSetUp"


_SELF_DROPPED_COPY = "sync.thisPcWasDroppedFrom"


_GENERIC_COPY = "sync.syncReportedAProblemDetails"


_DEVICE_SUFFIX = ".lgksync"


#: Kinds whose detail starts with a file name (``"<file>: reason"``) or is one.
_FILE_KINDS = frozenset({"corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch",
                         "unreadable", "stale-device", "implausible-counter", "view-unsigned", "view-forged"})


#: Kinds whose detail starts with a device id.
_DEVICE_KINDS = frozenset({"member-dropped", "member-added", "bad-name", "bad-peer-data", "bad-peer-record",
                           "implausible-vv", "epoch-behind",
                           "peer-epoch-behind", "no-endpoint", "peer-revoked", "peer-mismatch",
                           "group-mismatch", "peer-update-needed", "signer-changed", "peer-vault-rollback",
                           "witness-implausible"})


#: Issues that stop sync for good until the user acts; the banner offers "Reset sync on this PC".
RESET_KINDS = frozenset({"folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt",
                         "keyring-corrupt", "tampered", "identity-mismatch", "keyring-rollback"})


_ERROR_KINDS = RESET_KINDS | frozenset({
    "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable",
    "write-failed", "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
    "counter-exhausted", "vault-rollback",
})


_NOTICE_KINDS = frozenset({"counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self",
                           "unreachable", "no-endpoint", "lan-not-listening", "not-joined",
                           "peer-vault-rollback", "rollback-acknowledged",
                           "witness-implausible", "attachment-missing"})


#: Banner order: lower first.
_PRIORITY = (
    "vault-rollback", "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
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
            return t("sync.anotherDevice")
        if own_id is not None and head == own_id:
            return t("sync.thisPc")
        name = names.get(head) if kind != "bad-name" else None  # its name is the unreadable part
        return sanitize_name(name) if name else short_id(head)
    if kind in _FILE_KINDS:
        return t("sync.theFileName", name=sanitize_name(head, limit=60)) if head else t("sync.aSyncFile")
    if kind == "ignored-file":
        return sanitize_name(detail, limit=120) if detail else t("sync.someFiles")
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
        return t(_INSTALL_MISMATCH_COPY)
    if kind == "member-dropped" and own_id is not None and detail == own_id:
        return t(_SELF_DROPPED_COPY)
    key = _EPOCH_BEHIND_FOLDER_COPY if kind == "epoch-behind" and folder else ISSUE_COPY.get(kind)
    if key is None:
        return t(_GENERIC_COPY)
    template = t(key)
    subject = _subject(kind, detail, names or {}, own_id)
    if kind == "device-mismatch" and not detail.split(": ", 1)[0].strip().endswith(_DEVICE_SUFFIX):
        template = t("sync.sentDataSignedForA")
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
        if kind in ROLLBACK_KINDS:
            continue  # rollback_view shows these with their buttons
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
    "not-this-device": "sync.thisCodeIsFromA",
    "password": "sync.thatSyncPasswordIsNot",
    "password-reused": "sync.chooseANewSyncPassword",
    "weak-password": "sync.theSyncPasswordNeedsAt",
    "folder-in-use": "sync.thisFolderAlreadyHoldsA",
    "no-group": "sync.thereIsNoSyncGroup",
    "different-group": "sync.thisVaultAlreadySyncsWith",
    "keyring-changed": "sync.anotherDeviceChangedTheSync",
    "folder-error": "sync.theFolderCouldNotBe",
    "folder-missing": "sync.thatFolderDoesNotExist",
    "too-many-members": "sync.thisSyncGroupAlreadyHas",
    "cannot-remove-self": "sync.thisPcCannotRemoveItself",
    "already-joined": "sync.thisVaultIsAlreadyIn",
    "not-joined": "sync.thisVaultIsNotIn",
    "rejoin-required": "sync.thisVaultWasSetUp2",
    "not-member": "sync.thatDeviceIsNotIn",
    "missed-rotation": "sync.thisPcMissedAPassword",
    "offer-used-or-expired": "sync.thisPairingCodeWasUsed",
    "unreachable": "sync.theOtherDeviceCouldNot",
    "too-many-peers": "sync.theOtherDeviceAlreadyHas",
    "declined": "sync.theOtherDeviceDeclinedOr",
    "update-needed": "sync.updateLocalgatekeysOnThisPc",
    "bad-offer": "sync.thatIsNotAValid",
    "refused": "sync.theOtherDeviceRefusedThe2",
    "not-our-offer": "sync.thisPairingCodeBelongsTo",
    "already-has-folder": "sync.thisSyncGroupAlreadyUses",
    "folder-has-other-group": "sync.thatFolderHoldsADifferent",
    "different-group-key": "sync.thatFolderSSyncGroup",
    "epoch-mismatch": "sync.theSyncKeyInThat",
    "already-member": "sync.thisPcIsAlreadyIn",
    "lan-peer-removed": "sync.aWiFiDeviceWas2",
}


def error_text(exc: BaseException) -> str:
    """User copy for a refused sync action (``FolderSyncError``/``LanSyncError``/``KeyringError`` reason)."""
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str):
        if reason in ERROR_COPY:
            return t(ERROR_COPY[reason])
        if reason in ISSUE_COPY:
            return issue_text(type("Issue", (), {"kind": reason, "detail": ""})())
        return t("sync.syncCouldNotFinishThat")
    from ..session_guard import StaleSession

    if isinstance(exc, StaleSession) or type(exc).__name__ == "SyncAborted":
        return t("sync.theVaultLockedOrSync")
    return t("sync.syncCouldNotFinishThat")


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
    label = strength_label(score)
    if len(password) < MIN_SYNC_PASSWORD_LEN:
        return PasswordCheck(False, score, label, t("sync.passwordMinChars", count=MIN_SYNC_PASSWORD_LEN))
    if score < MIN_SYNC_PASSWORD_SCORE:
        return PasswordCheck(False, score, label, t("sync.tooEasyToGuessAdd"))
    if password != (confirm_password or ""):
        return PasswordCheck(False, score, label, t("sync.theTwoPasswordsDoNot"))
    return PasswordCheck(True, score, label, t("sync.good"))


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
        return None, t("sync.enterThisPcSAddress")
    host, sep, port_text = raw.rpartition(":")
    if not sep or not host:
        return None, t("sync.useAddressPortForExample")
    bracketed = host.startswith("[") and host.endswith("]")
    if bracketed:
        host = host[1:-1]
    elif ":" in host:
        return None, t("sync.putAnIpv6AddressIn")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None, t("sync.useThisPcSNumeric")
    if bracketed != (address.version == 6):
        return None, t("sync.useAddressPortForExample")
    if not _usable_lan_address(address):
        return None, t("sync.useThisPcSAddress")
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        return None, t("sync.useAPortBetween1024")
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
        return t("sync.expired")
    return t("sync.expiresIn", minutes=left // 60, seconds=f"{left % 60:02d}")


def ago_text(timestamp: int | None, now: float) -> str:
    if timestamp is None:
        return t("status.sync.never")
    age = max(0, int(now) - int(timestamp))
    if age < 60:
        return t("sync.lastSyncedJustNow")
    if age < 3600:
        return t("sync.lastSyncedMin", count=age // 60)
    if age < 86400:
        return t("sync.lastSyncedHours", count=age // 3600)
    return t("sync.lastSyncedDays", count=age // 86400)


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
            orphan, detail = "no-file", t("sync.hasNoSyncFileIn")
        elif member.file_written_at < now - STALE_AFTER_SECONDS:
            orphan, detail = "stale", t("sync.hasNotSyncedForOver2")
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


def rollback_issues(status: Any) -> list[Any]:
    """Every ``vault-rollback`` / ``peer-vault-rollback`` issue of the last runs (any transport), deduplicated."""
    if status is None:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[Any] = []
    pools = [getattr(status, "issues", ()) or ()]
    pools += [getattr(t, "issues", ()) or () for t in getattr(status, "transports", ()) or ()]
    for pool in pools:
        for issue in pool:
            key = (str(getattr(issue, "kind", "")), str(getattr(issue, "detail", "") or ""))
            if key[0] in ROLLBACK_KINDS and key not in seen:
                seen.add(key)
                out.append(issue)
    return out


def rollback_view(status: Any, group: GroupSnapshot | None, *,
                  hidden: Iterable[tuple[str, str]] = ()) -> dict[str, Any]:
    """The rollback banner: ``own`` (this vault looks restored) and ``peers`` (a peer looks restored).

    *hidden*: ``(kind, detail)`` pairs the user already acknowledged or dismissed since the last run.
    """
    names = group.names() if group is not None else {}
    own_id = group.device_id if group is not None else None
    skip = set(hidden)
    own: dict[str, Any] | None = None
    peers: list[dict[str, Any]] = []
    for issue in rollback_issues(status):
        kind, detail = str(issue.kind), str(getattr(issue, "detail", "") or "")
        if (kind, detail) in skip:
            continue
        if kind == "vault-rollback" and own is None:
            own = {"kind": kind, "severity": issue_severity(kind), "title": t(ROLLBACK_TITLE),
                   "text": t(ISSUE_COPY[kind]), "action": t(ROLLBACK_ACTION)}
        elif kind == "peer-vault-rollback" and detail and detail != own_id:
            peers.append({"kind": kind, "severity": issue_severity(kind), "id": detail,
                          "text": issue_text(issue, names=names, own_id=own_id), "action": t(PEER_ROLLBACK_DISMISS)})
    return {"own": own, "peers": peers}


def _conflicts_text(count: int) -> str:
    if count <= 0:
        return ""
    return t("sync.conflictCopies", count=count)


def _folder_card(status: Any, group: GroupSnapshot | None, *, now: float, available: bool,
                 state_corrupt: bool, names: Mapping[str, str], own: str | None) -> CardView:
    title = t("sync.cloudFolder")
    transport = _transport(status, "folder")
    issues = _issue_views(getattr(transport, "issues", ()) or (), names, own)
    banner = issues[0] if issues else None
    running = bool(getattr(status, "running", False))
    last = ago_text(getattr(transport, "last_sync", None), now)
    if not available:
        return CardView("folder", title, "unavailable", t("sync.syncRunsWhileTheVault"))
    if state_corrupt:
        return CardView("folder", title, "broken", t("sync.syncSettingsOnThisPc"),
                        actions=frozenset({"reset"}))
    if group is None:
        return CardView("folder", title, "off",
                        t("sync.offKeepYourDevicesIn"),
                        actions=frozenset({"create-group", "join-folder"}))
    unacked = set(group.unacked)
    members = tuple(
        MemberView(m.device_id, sanitize_name(m.name),
                   t("syncStatusPage.thisPc") if m.is_self else (t("sync.addedByAnotherDeviceNot")
                                                if m.device_id in unacked else ""),
                   m.is_self, not m.is_self)
        for m in group.members)
    if not group.folder_path:
        if not group.install_ok:
            return CardView("folder", title, "lan-only", t("sync.notUsedThisVaultSyncs"))
        return CardView("folder", title, "lan-only", t("sync.notUsedThisVaultSyncs"),
                        actions=frozenset({"add-folder", "use-folder"}), hint=t(LAN_ONLY_FOLDER_HINT))
    folder_text = t("sync.folderLine", name=sanitize_name(group.folder_path, limit=80))
    common = dict(members=members, last_sync_text=last, banner=banner, issues=issues)
    if not group.install_ok:
        return CardView("folder", title, "rejoin", t("sync.needsJoinAgain", folder=folder_text),
                        actions=frozenset({"join-folder", "leave", "reset"}), **common)
    kinds = {issue.kind for issue in issues}
    if "folder-has-other-group" in kinds:
        actions = {"leave", "reset", "sync-now"}
        state, text = "stopped", t("sync.stoppedTheFolderHoldsAnother")
    elif kinds & {"rotation-conflict", "removed-or-conflict", "rejoin-required"}:
        actions = {"join-folder", "leave", "reset", "sync-now"}
        state, text = "stopped", t("sync.stoppedJoinTheFolderAgain")
    elif kinds & (RESET_KINDS - {"state-corrupt"}):
        actions = {"join-folder", "leave", "reset", "sync-now"}
        state, text = "stopped", t("sync.stoppedTheSyncFolderNeeds")
    else:
        actions = {"sync-now", "change-password", "remove-device", "leave"}
        if orphan_members(group, now=now):
            actions.add("show-orphans")
        if unacked & {m.device_id for m in group.members}:
            actions.add("ack-members")
        state, text = "on", t("sync.on")
    if running:
        actions.discard("sync-now")
        text = f"{text} {t('sync.syncingNow')}"
    return CardView("folder", title, state, f"{text} {folder_text}", actions=frozenset(actions), **common)


def _wifi_card(status: Any, group: GroupSnapshot | None, *, now: float, available: bool, endpoint: str,
               state_corrupt: bool, names: Mapping[str, str], own: str | None) -> CardView:
    title = t("sync.wiFiThisNetwork")
    transport = _transport(status, "lan")
    in_folder = group is not None and bool(group.folder_path)
    issues = _issue_views(getattr(transport, "issues", ()) or (), names, own, folder=in_folder)
    banner = issues[0] if issues else None
    running = bool(getattr(status, "running", False))
    if not available:
        return CardView("wifi", title, "unavailable", t("sync.syncRunsWhileTheVault"))
    if state_corrupt:
        return CardView("wifi", title, "broken", t("sync.syncSettingsOnThisPc"))
    peers: tuple[MemberView, ...] = ()
    if group is not None:
        peers = tuple(
            MemberView(p.device_id, sanitize_name(names.get(p.device_id) or short_id(p.device_id)),
                       t("sync.atEndpoint", endpoint=sanitize_name(p.endpoint, limit=48)) if p.endpoint else t("sync.connectsToThisPc"),
                       False, True)
            for p in group.lan_peers)
    lan_only = group is not None and not group.folder_path
    if not endpoint:
        actions = {"wifi-enable"} | ({"join-qr"} if group is None else set())
        if lan_only:
            actions.add("leave")
        return CardView("wifi", title, "off",
                        t("sync.offSyncWithYourPhone"),
                        members=peers, actions=frozenset(actions), banner=banner, issues=issues)
    where = t("sync.listensOn", endpoint=endpoint)
    if group is None:
        return CardView("wifi", title, "ready", t("sync.readyShowQr", where=where),
                        actions=frozenset({"show-qr", "join-qr", "wifi-disable"}), banner=banner, issues=issues)
    common = dict(members=peers, last_sync_text=ago_text(getattr(transport, "last_sync", None), now),
                  banner=banner, issues=issues)
    if not group.install_ok:
        return CardView("wifi", title, "rejoin", t("sync.needsToBeSetUp"),
                        actions=frozenset({"leave", "reset", "wifi-disable"}), **common)
    actions = {"show-qr", "sync-now", "wifi-disable"}
    if peers:
        actions.add("remove-device")
    if lan_only:
        # Includes epoch-behind in a Wi-Fi-only group: its copy says leave, then pair again.  A folder
        # member is told to let the folder sync or join again instead, so Leave is not offered there.
        actions.add("leave")
    text = t("sync.onWhere", where=where)
    if running:
        actions.discard("sync-now")
        text = f"{text} {t('sync.syncingNow')}"
    if not peers:
        text = f"{text} {t('sync.noDevicesPaired')}"
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
        global_views = (IssueView("state-corrupt", "error", t(ISSUE_COPY["state-corrupt"]), True), *global_views)
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
            named.append(t("sync.itemNotSyncedNamed", name=sanitize_name(name)))
        else:
            unnamed.append(item_id)
    if unnamed:
        named.append(t("sync.itemsNotSynced", count=len(unnamed)))
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
            t("sync.addACloudFolder"),
            t("sync.chooseTheFolderYourCloud"),
            True, t("sync.addingTheCloudFolder"),
            t("sync.theCloudFolderWasAdded"),
            add_folder_job)
    if action == "use-folder":
        return FolderSetup(
            t("sync.useThisGroupSCloud"),
            t("sync.chooseTheFolderAnotherDevice"),
            False, t("sync.connectingTheCloudFolder"), t("sync.thisPcNowAlsoSyncs"),
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


def acknowledge_rollback_job():
    """The user (or a restore made in the app) confirmed this vault's older copy (``vault-rollback``)."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.vault_bridge import acknowledge_vault_rollback

        return acknowledge_vault_rollback(session, lease)

    return job


def dismiss_peer_rollback_job(peer_id: str):
    """The user dismissed ``peer-vault-rollback`` for *peer_id*."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.vault_bridge import forget_peer_generation

        return forget_peer_generation(session, lease, peer_id)

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


def refind_job(qr_text: str, install_id: str):
    """"Find again": store the new address of an already paired device from its QR text."""

    def job(session: Any, lease: Any, gate: Any) -> Any:
        from ..sync.lan_sync import refind_from_qr

        return refind_from_qr(qr_text, session, lease, install_id=install_id)

    return job


def _noop_job(session: Any, lease: Any, gate: Any) -> None:
    """Lets ``submit`` re-read the state (listener start/stop after a settings change)."""
    return None


_ACTION_LABELS = {
    "sync-now": "syncStatusPage.syncNow",
    "create-group": "sync.createSyncGroup",
    "join-folder": "sync.joinAFolder",
    "add-folder": "sync.addACloudFolderTo",
    "use-folder": "sync.useThisGroupSCloud2",
    "change-password": "sync.changeSyncPassword",
    "remove-device": "sync.removeADevice",
    "show-orphans": "sync.unusedMembers",
    "ack-members": "sync.theseAreMyDevices",
    "leave": "sync.leaveSync",
    "reset": "sync.resetSyncOnThisPc2",
    "show-qr": "sync.showQrCode",
    "join-qr": "sync.joinByQrText",
    "wifi-enable": "sync.turnOnWiFiSync",
    "wifi-disable": "sync.turnOffWiFiSync",
}


_ACTION_ORDER = ("sync-now", "show-qr", "join-qr", "create-group", "join-folder", "add-folder", "use-folder",
                 "ack-members", "change-password", "remove-device", "show-orphans", "wifi-enable", "wifi-disable", "leave", "reset")


_PRIMARY = frozenset({"sync-now", "create-group", "add-folder", "show-qr", "wifi-enable"})
