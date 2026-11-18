"""Shared collections for the WebView UI (sub-plan 07 Task 3): the Share section of a collection.

One page call per action, run under the vault lock like every other page call, so a share action
never interleaves with a sync run's vault writes.  The share group itself lives in
``sync.share_group``; the folder transport (``FolderSync(share=...)``) syncs it in the sync
service's rounds.  This service:

* shares a collection through a folder the user picks (password typed twice, the "Members can
  edit" choice fixed at creation: changing it means sharing again), joins one from a folder, and
  joins again after a lost join (``superseded``);
* shows the members (owner, member, waiting for approval) and the people the owner removed;
  approval names each waiting person in a confirmation before the owner signs them in;
* offers the owner of a share v1 group the upgrade to share v2 (items keyed to the approved devices only,
  ``docs/superpowers/specs/2026-11-12-collections-crypto-gating.md``): the share password typed twice;
* removes a member with a NEW share password (the removed person knows the old one), writing the
  owner's removal notice and the rotated keyring to the folder; this works after Pro lapsed;
* turns the share run's issues into copy: ``keyring-merged`` is information, ``superseded`` says
  "join again", ``share-removed`` says the collection's items went to the trash.

Pro: creating and joining show the upgrade sheet on the free plan (``pro_required``).  Share
passwords are only ever in the call's arguments and are dropped when it returns; nothing here logs,
and no password, key or keyring reaches the page.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..api.result import ApiError
from ..i18n import t
from .licence_view import pro_required
from .sync_view import (
    check_sync_password,
    default_device_name,
    error_text,
    issue_text,
    sanitize_name,
)

#: Share run issue kinds -> copy (anything else: the sync page's copy for that kind).
ISSUE_COPY = {
    "superseded": "collectionShare.superseded",
    "share-removed": "collectionShare.removedFromShare",
    "keyring-merged": "collectionShare.keyringMerged",
    "awaiting-approval": "collectionShare.awaitingApproval",
    "pro-required": "vault.proNeededSharing",
    "rejoin-required": "collectionShare.rejoinRequired",
    "folder-missing": "collectionShare.folderMissing",
    "trash-full": "collectionShare.removedTrashFull",
    "item-error": "collectionShare.removedItemError",
    "history-quota": "collectionShare.removedItemError",
    "history-error": "collectionShare.removedItemError",
    "tampered": "collectionShare.tampered",
    "other-group-replaced": "collectionShare.otherGroupReplaced",
    "update-required": "collectionShare.updateRequired",
}
#: Refusals of a share action (``ShareGroupError`` / ``KeyringError`` reasons) -> copy.
ERROR_COPY = {
    "already-shared": "collectionShare.alreadyShared",
    "no-collection": "collectionShare.noCollection",
    "not-share": "collectionShare.notAShare",
    "personal-group": "collectionShare.notAShare",
    "already-joined": "collectionShare.alreadyJoined",
    "collection-exists": "collectionShare.collectionExists",
    "not-owner": "collectionShare.notOwner",
    "not-pending": "collectionShare.notPending",
    "not-joined": "collectionShare.notShared",
    "password": "collectionShare.wrongPassword",
    "password-reused": "collectionShare.passwordReused",
    "too-many-members": "collectionShare.tooManyMembers",
    "no-link": "collectionShare.notShared",
    "shared-here": "collectionShare.forgetLinkSharedHere",
    "already-upgraded": "collectionShare.alreadyUpgraded",
    "newer-format": "collectionShare.updateRequired",
}
_ERROR_ISSUES = frozenset({"tampered", "bad-owner", "bad-owner-sig", "state-corrupt", "keyring-corrupt",
                           "update-required"})
_NAME_BYTES = 64


def _install_id() -> str:
    from ..sync.install import load_or_create_install_id

    return load_or_create_install_id()


def _refusals() -> tuple[type[BaseException], ...]:
    """What a share action may refuse with (a stable ``reason``, or the collection limit)."""
    from ..item_schema import ItemSchemaError
    from ..sync.keyring import KeyringError
    from ..sync.share_group import ShareGroupError

    return ShareGroupError, KeyringError, ItemSchemaError


def _member_name(value: Any) -> str:
    """The name the other people see for this PC: what the user typed, else the generic PC name."""
    name = sanitize_name(value, limit=40).strip()
    while name and len(name.encode("utf-8")) > _NAME_BYTES:
        name = name[:-1].rstrip()
    return name or default_device_name()


class CollectionShareService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *, sync: Any = None,
                 changed: Callable[[], None] | None = None, install_id: Callable[[], str] = _install_id,
                 kdf: tuple[int, int, int] | None = None) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._sync = sync  # SyncWebService: the share runs' status and "sync now"
        self._changed = changed or (lambda: None)
        self._install_id = install_id
        self._kdf = kdf  # tests only: a cheap key derivation
        self._folders: dict[str, str] = {}
        from .secrets import SecretService

        self._auth = SecretService(controller, port)

    # ------------------------------------------------------------------ helpers
    def _session(self) -> Any:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        controller.require_lease(controller.guard.lease())
        return controller.session

    @staticmethod
    def _sg() -> Any:
        from ..sync import share_group

        return share_group

    def _fail(self, exc: BaseException) -> ApiError:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, str) and reason in ERROR_COPY:
            return ApiError(reason, t(ERROR_COPY[reason]))
        if isinstance(reason, str):
            return ApiError(reason, error_text(exc))
        return ApiError("share_failed", str(exc) or t("collectionShare.failed"))  # the collection limit

    def _collection(self, session: Any, collection_id: str) -> dict[str, Any]:
        from ..travel import visible_collections

        # A travel-hidden collection is absent here too: it cannot be shared or left until travel mode is off.
        row = next((c for c in visible_collections(session, session.collections.list())
                    if c.get("id") == collection_id), None)
        if row is None:
            raise ApiError("invalid", t("collectionShare.noCollection"))
        return row

    def _group(self, session: Any, collection_id: str) -> Any:
        sg = self._sg()
        try:
            return next((g for g in sg.list_share_groups(session) if g.collection_id == collection_id), None)
        except sg.ShareGroupError as exc:
            raise self._fail(exc) from None

    def _shared(self, session: Any, collection_id: str) -> Any:
        group = self._group(session, collection_id)
        if group is None:
            raise ApiError("not-joined", t("collectionShare.notShared"))
        return group

    def _folder(self, token: str) -> str:
        """The folder the user picked for *token*; the token stays valid until an action succeeds with it."""
        folder = self._folders.get(str(token or ""))
        if not folder:
            raise ApiError("invalid", t("collectionShare.chooseFolderFirst"))
        return folder

    def _fs(self, folder: str, group_id: str | None = None) -> Any:
        from ..sync.folder_transport import FolderSync

        return FolderSync(folder, install_id=self._install_id(), share=group_id, _kdf_override=self._kdf)

    @staticmethod
    def _require_strong(password: str, confirm: str) -> None:
        check = check_sync_password(password, confirm)
        if not check.ok:
            raise ApiError("invalid", check.message)

    def _require_pro(self) -> None:
        sg = self._sg()
        if not sg.share_sync_allowed():
            raise pro_required(self._port, sg.ProRequired())

    def _write_keyring(self, session: Any, group_id: str, folder: str | None) -> bool:
        """Put this device's trusted keyring of *group_id* into *folder* now (the share run also does it).

        Only into a folder without a keyring or over an older state of the same group (a remove's rotation
        is a later epoch, so it is written), like lgk-core and LGKCore ``writeShareKeyring``.  Anything else
        (someone's join that arrived meanwhile, another group, bytes that do not parse) is left to the share
        run, which reconciles or repairs it (``share_group.restores_over``): False.
        """
        if not folder:
            return False
        from ..sync.folder_transport import FolderSyncError
        from ..sync.keyring import KeyringError, parse_keyring

        sg = self._sg()
        fs = self._fs(folder, group_id)
        try:
            try:
                current: bytes | None = fs.read_keyring_bytes()
            except FileNotFoundError:
                current = None
            ring = sg.share_keyring(session, group_id)
            if current == ring:
                return True
            trusted = parse_keyring(ring)
            if current is not None:
                try:
                    if not sg.grows_from(parse_keyring(current), trusted):
                        return False
                except KeyringError:
                    return False
            fs.write_keyring(trusted, expected=current)
        except (FolderSyncError, OSError):
            return False
        return True

    def _after_change(self) -> None:
        self._controller.touch()
        self._changed()
        service = getattr(self._sync, "service", None)
        if service is not None and getattr(service, "licence_only", False) is not True:
            try:
                service.run_now()
            except Exception:  # noqa: BLE001, S110 - the next scheduled run syncs the share
                pass

    def _confirm_handover(self) -> None:
        """The master password (never Windows Hello) before a collection's items go to a folder."""
        lease = self._controller.guard.lease()
        self._auth.reauthenticate(t("collectionShare.confirmToShare"), lease, allow_hello=False)
        self._controller.require_lease(lease)

    def _ask(self, title: str, text: str) -> None:
        if not self._port.confirm(title, text):
            raise ApiError("cancelled", t("error.cancelled"))

    # ------------------------------------------------------------------- status
    def _share_status(self, group_id: str) -> Any:
        status = getattr(self._sync, "status", None)
        return next((s for s in getattr(status, "shares", ()) or () if getattr(s, "name", None) == group_id), None)

    @staticmethod
    def _issue(issue: Any) -> dict[str, Any]:
        from ..sync.service import NOTICE_KINDS

        kind = str(getattr(issue, "kind", ""))
        key = ISSUE_COPY.get(kind)
        text = t(key) if key else issue_text(issue, folder=True)
        severity = "info" if kind in NOTICE_KINDS else ("error" if kind in _ERROR_ISSUES else "warning")
        shown = {"kind": kind, "severity": severity, "text": text}
        if kind == "superseded":
            shown["action"] = "rejoin"
        return shown

    def _status(self, group_id: str) -> dict[str, Any] | None:
        run = self._share_status(group_id)
        issues = list(getattr(run, "issues", ()) or ())
        if not issues:
            return None
        shown = [self._issue(i) for i in issues]
        rank = {"error": 0, "warning": 1, "info": 2}
        return sorted(shown, key=lambda s: rank[s["severity"]])[0]

    def _removed_notice(self, collection_id: str) -> dict[str, Any] | None:
        """This PC was removed from *collection_id*'s share in this unlock: say so (the group is gone)."""
        status = getattr(self._sync, "status", None)
        for run in getattr(status, "shares", ()) or ():
            for issue in getattr(run, "issues", ()) or ():
                if issue.kind == "share-removed" and issue.detail == collection_id:
                    return self._issue(issue)
        return None

    # --------------------------------------------------------------------- view
    def view(self, collection_id: str) -> dict[str, Any]:
        session = self._session()
        sg = self._sg()
        row = self._collection(session, collection_id)
        base = {"collection": {"id": str(row["id"]), "name": str(row.get("name", ""))},
                "pro": sg.share_sync_allowed(), "pro_text": t("vault.proNeededSharing"),
                "help": t("collectionShare.help"), "owner_loss": t("collectionShare.ownerLoss")}
        group = self._group(session, collection_id)
        if group is None:
            link = sg.received_share_link(session, collection_id)
            linked = None
            if link is not None:
                # Shared by another of this person's devices: sharing it again here is refused (already-shared).
                linked = {"text": t("collectionShare.linkedOwner" if link["role"] == "owner"
                                    else "collectionShare.linkedMember"),
                          "forget_hint": t("collectionShare.forgetLinkHint")}
            return {**base, "shared": False, "linked": linked, "intro": t("collectionShare.intro"),
                    "mode_hint": t("collectionShare.modeFixed"), "status": self._removed_notice(collection_id)}
        try:
            info = sg.share_info(session, group.group_id)
            state = sg.share_state(session, group.group_id)
            removed = sg.removed_members(session, group.group_id)
        except sg.ShareGroupError as exc:
            raise self._fail(exc) from None
        own = state.device_id
        is_owner = info["role"] == "owner"

        def name(value: Any) -> str:
            return sanitize_name(value) or t("collectionShare.unnamed")

        members = []
        for m in group.members:
            kind = "owner" if m.device_id == group.owner else ("member" if m.approved else "pending")
            members.append({"id": m.device_id, "name": name(m.name), "state": kind,
                            "state_text": t(f"collectionShare.state.{kind}"), "is_self": m.device_id == own,
                            "removable": is_owner and m.device_id != own})
        return {**base, "shared": True, "role": info["role"], "is_owner": is_owner, "mode": group.shared_mode,
                "mode_text": t("collectionShare.modeEdit" if group.shared_mode == "edit" else "collectionShare.modeRead"),
                "mode_hint": t("collectionShare.modeFixed"), "folder": state.folder_path or "",
                "members": members,
                "pending": [{"id": m["id"], "name": m["name"]} for m in members
                            if is_owner and m["state"] == "pending"],
                "removed": [{"name": name(n), "at": int(at)} for n, at in removed] if is_owner else [],
                # Share v1 on the owner's device: offer the upgrade (items keyed to approved devices only).
                "upgrade": ({"title": t("collectionShare.upgradeTitle"), "text": t("collectionShare.upgradeText")}
                            if is_owner and group.version == 1 else None),
                "status": self._status(group.group_id),
                # Shared from two of this person's devices (re-review wave B, B1): one share should go.
                "twice": t("collectionShare.sharedTwice") if sg.shared_twice(session, collection_id) else None}

    # ------------------------------------------------------------------ actions
    def choose_folder(self) -> dict[str, Any]:
        self._session()
        folder = self._dialogs.choose_folder(t("collectionShare.chooseFolder"))
        if not folder:
            raise ApiError("cancelled", t("error.noFolderChosen"))
        token = secrets.token_urlsafe(12)
        self._folders[token] = str(folder)
        return {"token": token, "path": str(folder)}

    def create(self, collection_id: str, token: str, password: str, confirm: str, can_edit: bool,
               name: str = "") -> dict[str, Any]:
        sg = self._sg()
        session = self._session()
        self._require_pro()
        row = self._collection(session, collection_id)
        folder = self._folder(token)
        try:
            self._require_strong(password, confirm)
            if not Path(folder).is_dir():
                raise ApiError("folder-missing", t("collectionShare.folderMissing"))
            if self._fs(folder).keyring_path.exists():
                raise ApiError("folder-in-use", t("collectionShare.folderInUse"))
            self._confirm_handover()
            try:
                group = sg.create_share_group(session, collection_id, password=password, device=_member_name(name),
                                              shared_mode="edit" if can_edit else "read",
                                              install_id=self._install_id(), _kdf_override=self._kdf)
            except _refusals() as exc:
                raise self._fail(exc) from None
        finally:
            password = confirm = ""
        sg.set_share_folder(session, group.group_id, folder)
        if not self._write_keyring(session, group.group_id, folder):
            sg.leave_share_group(session, group.group_id)  # nothing reached the folder: undo
            raise ApiError("folder", t("collectionShare.folderNotWritable"))
        self._folders.pop(token, None)
        self._after_change()
        return {"message": t("collectionShare.sharedDone", name=str(row.get("name", ""))), **self.view(collection_id)}

    def _join(self, folder: str, password: str, name: str) -> Any:
        sg = self._sg()
        session = self._session()
        if not password:
            raise ApiError("invalid", t("collectionShare.enterPassword"))
        try:
            raw = self._fs(folder).read_keyring_bytes()
        except FileNotFoundError:
            raise ApiError("no-share", t("collectionShare.noShareInFolder")) from None
        except OSError:
            raise ApiError("folder-unreadable", t("collectionShare.folderUnreadable")) from None
        try:
            group = sg.join_share_group(session, raw, password=password, device=_member_name(name),
                                        install_id=self._install_id(), _kdf_override=self._kdf)
        except _refusals() as exc:
            raise self._fail(exc) from None
        sg.set_share_folder(session, group.group_id, folder)
        self._write_keyring(session, group.group_id, folder)  # a lost race is reported by the run (superseded)
        self._after_change()
        return group

    def join(self, token: str, password: str, name: str = "") -> dict[str, Any]:
        self._session()
        self._require_pro()
        folder = self._folder(token)
        try:
            group = self._join(folder, password, name)
        finally:
            password = ""
        self._folders.pop(token, None)
        return {"message": t("collectionShare.joinedDone", name=sanitize_name(group.name)),
                "collection_id": group.collection_id, **self.view(group.collection_id)}

    def rejoin(self, collection_id: str, password: str, name: str = "") -> dict[str, Any]:
        """Join again after someone else's join at the same moment won (``superseded``), from the same folder."""
        sg = self._sg()
        session = self._session()
        self._require_pro()
        group = self._shared(session, collection_id)
        folder = sg.share_state(session, group.group_id).folder_path
        if not folder:
            raise ApiError("invalid", t("collectionShare.chooseFolderFirst"))
        try:
            self._join(folder, password, name)
        finally:
            password = ""
        return {"message": t("collectionShare.joinedDone", name=sanitize_name(group.name)), **self.view(collection_id)}

    def approve(self, collection_id: str, device_ids: list[str]) -> dict[str, Any]:
        """Let waiting people in: the confirmation names each one; only ids that are waiting count."""
        sg = self._sg()
        session = self._session()
        group = self._shared(session, collection_id)
        try:
            waiting = {m.device_id: m for m in sg.pending_members(session, group.group_id)}
        except sg.ShareGroupError as exc:
            raise self._fail(exc) from None
        chosen = [d for d in dict.fromkeys(device_ids) if d in waiting]
        if not chosen or len(chosen) != len(set(device_ids)):
            raise ApiError("invalid", t("collectionShare.notPending"))
        names = ", ".join(sanitize_name(waiting[d].name) or t("collectionShare.unnamed") for d in chosen)
        collection = sanitize_name(group.name)
        self._ask(t("collectionShare.approveTitle"), t("collectionShare.approveText", names=names, name=collection))
        try:
            sg.approve_members(session, group.group_id, chosen, _kdf_override=self._kdf)
        except _refusals() as exc:
            raise self._fail(exc) from None
        self._write_keyring(session, group.group_id, sg.share_state(session, group.group_id).folder_path)
        self._after_change()
        return {"message": t("collectionShare.approvedDone", names=names), **self.view(collection_id)}

    def remove(self, collection_id: str, device_id: str, password: str, confirm: str) -> dict[str, Any]:
        """Remove one person (owner only, also after Pro lapsed) with a NEW share password."""
        sg = self._sg()
        session = self._session()
        group = self._shared(session, collection_id)
        member = next((m for m in group.members if m.device_id == device_id), None)
        state = sg.share_state(session, group.group_id)
        if member is None or device_id == state.device_id:
            raise ApiError("invalid", t("collectionShare.notAMember"))
        person = sanitize_name(member.name) or t("collectionShare.unnamed")
        collection = sanitize_name(group.name)
        try:
            self._require_strong(password, confirm)
            self._ask(t("collectionShare.removeTitle", person=person),
                      t("collectionShare.removeText", person=person, name=collection))
            try:
                notice = sg.remove_member(session, group.group_id, device_id, new_password=password,
                                          _kdf_override=self._kdf)
            except _refusals() as exc:
                raise self._fail(exc) from None
        finally:
            password = confirm = ""
        folder = state.folder_path
        # The notice first: a removed PC that sees the new keyring finds the notice beside it.
        published = bool(folder) and self._fs(folder, group.group_id).publish_share_notice(device_id, notice)
        written = self._write_keyring(session, group.group_id, folder)
        self._after_change()
        message = t("collectionShare.removedDone", person=person)
        if not (published and written):
            message = f"{message} {t('collectionShare.removedNotWritten')}"
        return {"message": message, **self.view(collection_id)}

    def upgrade(self, collection_id: str, password: str, confirm: str) -> dict[str, Any]:
        """Owner only (also after Pro lapsed): upgrade a share v1 group to share v2.

        The share password is typed twice (the current one may be kept: it no longer opens any item).
        The rotated keyring is written now when the folder allows it, else at the next share run.
        """
        sg = self._sg()
        session = self._session()
        group = self._shared(session, collection_id)
        try:
            self._require_strong(password, confirm)
            try:
                sg.upgrade_share(session, group.group_id, password=password, _kdf_override=self._kdf)
            except _refusals() as exc:
                raise self._fail(exc) from None
        finally:
            password = confirm = ""
        written = self._write_keyring(session, group.group_id, sg.share_state(session, group.group_id).folder_path)
        self._after_change()
        message = t("collectionShare.upgradedDone")
        if not written:
            message = f"{message} {t('collectionShare.removedNotWritten')}"
        return {"message": message, **self.view(collection_id)}

    def forget_link(self, collection_id: str) -> dict[str, Any]:
        """Forget a share link another of this person's devices published (final review finding 4): for a
        device that was lost or reset. A device that still holds the share publishes its link again."""
        sg = self._sg()
        session = self._session()
        row = self._collection(session, collection_id)
        if sg.received_share_link(session, collection_id) is None:
            raise ApiError("no-link", t("collectionShare.notShared"))
        collection = sanitize_name(row.get("name", ""))
        self._ask(t("collectionShare.forgetLinkTitle"), t("collectionShare.forgetLinkText", name=collection))
        try:
            sg.forget_share_link(session, collection_id)
        except _refusals() as exc:
            raise self._fail(exc) from None
        self._after_change()
        return {"message": t("collectionShare.forgetLinkDone", name=collection), **self.view(collection_id)}

    def leave(self, collection_id: str) -> dict[str, Any]:
        sg = self._sg()
        session = self._session()
        group = self._shared(session, collection_id)
        owner = sg.share_info(session, group.group_id)["role"] == "owner"
        collection = sanitize_name(group.name)
        if owner:
            self._ask(t("collectionShare.stopTitle"), t("collectionShare.stopText", name=collection))
        else:
            self._ask(t("collectionShare.leaveTitle"), t("collectionShare.leaveText", name=collection))
        sg.leave_share_group(session, group.group_id)
        self._after_change()
        return {"message": t("collectionShare.stoppedDone" if owner else "collectionShare.leftDone", name=collection),
                **self.view(collection_id)}
