"""Windows services for the 2026-11-15 feature pack: access rules, item history, travel mode, clean up.

Contract: ``docs/superpowers/specs/2026-11-15-feature-pack-contract.md`` sections 1-4.  The pure rules live in
``access_policy``, ``item_history``, ``travel`` and ``hygiene`` (shared vectors under ``tests/vectors``); this
module only reads and writes the unlocked session, asks for re-authentication and gates Pro features.
"""
from __future__ import annotations

import copy
import threading
import time
from collections.abc import Iterable
from typing import Any

from .. import access_policy, hygiene, item_history, travel
from ..api.result import ApiError
from ..i18n import t
from ..vault import ProFeatureRequired, VaultError, require_pro_feature

CREDENTIAL_KINDS = ("web", "desktop")


# ----------------------------------------------------------------------------------- shared helpers
class _Base:
    def __init__(self, controller: Any, port: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._auth = SecretService(controller, port)
        self._lock = threading.RLock()

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    def _require(self, lease: Any) -> None:
        self._controller.require_lease(lease)

    @staticmethod
    def _pro(session: Any, feature: str) -> bool:
        allowed = getattr(session, "pro_features", None)
        return allowed is None or feature in allowed

    def _require_pro(self, session: Any, feature: str) -> None:
        from .licence_view import pro_required

        try:
            require_pro_feature(session, feature)
        except ProFeatureRequired as exc:
            raise pro_required(self._port, exc) from None


def _payload(session: Any) -> dict[str, Any]:
    return session._require_payload()


def _record(session: Any, ref: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """``(ns, live record)`` of a ref, straight from the payload (the caller never hands it out).

    A travel-hidden id is refused like a missing one (finding L7)."""
    from .secrets import refuse_travel_hidden

    refuse_travel_hidden(session, ref.get("id"))
    payload = _payload(session)
    if ref.get("source") == "credential":
        rows, ns = payload.get("entries", []), "entry"
    else:
        rows, ns = session._require_typed_catalog().get("items", []), "item"
    for row in rows:
        if isinstance(row, dict) and str(row.get("id")) == str(ref.get("id")):
            return ns, row
    raise ApiError("not_found", t("share.thisItemNoLongerExists"))


def _known_collections(session: Any) -> set[str]:
    rows = session._require_typed_catalog().get("collections", [])
    return {str(row["id"]) for row in rows if isinstance(row, dict) and "id" in row}


def _replace(session: Any, ns: str, current: dict[str, Any], proposed: dict[str, Any], change_type: str) -> None:
    """Write ``proposed`` over the live record ``current`` with a history row of kind ``change_type``."""
    if ns == "entry":
        session.mark_history_change([str(current.get("id"))], change_type)
        original = copy.deepcopy(current)
        current.clear()
        current.update(proposed)
        try:
            session.save()
        except BaseException:
            current.clear()
            current.update(original)
            raise
        return
    from ..item_schema import validate_item
    from ..item_service import check_writable

    proposed = copy.deepcopy(proposed)
    proposed["id"] = current["id"]
    proposed["created_at"] = current["created_at"]
    proposed["revision"] = int(current.get("revision") or 0) + 1
    proposed = validate_item(proposed, known_collection_ids=_known_collections(session))
    check_writable(session, current, proposed)
    original = copy.deepcopy(current)
    history = getattr(session, "history", None)
    if history is not None:
        history.record_before_change(original, change_type=change_type, persist=False)
    current.clear()
    current.update(proposed)
    try:
        session.save()
    except BaseException:
        current.clear()
        current.update(original)
        raise


def _title(record: dict[str, Any]) -> str:
    return str(record.get("label") or record.get("title") or "")


def _ref_of(record: dict[str, Any]) -> dict[str, Any]:
    kind = str(record.get("kind") or "")
    return {"source": "credential" if kind in CREDENTIAL_KINDS else "typed", "id": str(record.get("id")), "kind": kind}


# ------------------------------------------------------------------------------------- access rules
class AccessRulesService(_Base):
    """``scope.access`` plus the two strict policy switches of a login (contract section 4)."""

    def __init__(self, controller: Any, port: Any, extras: Any) -> None:
        super().__init__(controller, port)
        self._extras = extras

    def _detail(self, session: Any, ref: dict[str, Any]) -> dict[str, Any]:
        if ref.get("source") != "credential":
            raise ApiError("invalid", t("loginExtras.chooseALogin"))
        from .secrets import refuse_travel_hidden

        refuse_travel_hidden(session, ref["id"])
        detail = session.credential_detail(ref["id"])
        if detail is None:
            raise ApiError("not_found", t("loginExtras.credentialIsNoLongerAvailable"))
        return detail

    def _view(self, session: Any, detail: dict[str, Any]) -> dict[str, Any]:
        raw = access_policy.access_of(detail)
        unknown = access_policy.access_unknown(raw)
        known = raw if isinstance(raw, dict) and not unknown else {}
        policy = access_policy.normalized_policy(detail.get("policy"))
        rules = access_policy.effective(detail, access_policy.DEVICE_COMPUTER, access_policy.local_today())
        return {"access": {"copy": "once" if known.get("copy", "normal") != "normal" else "normal",
                           "phones": "view" if known.get("phones", "full") != "full" else "full",
                           "expires": str(known.get("expires") or "")},
                "reauth": policy["require_master_password"], "never_fill": policy["fill"] == "never",
                "unknown": unknown, "expired": rules["expired"],
                "pro": self._pro(session, "access_policies")}

    def get(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_lease()
        detail = self._detail(session, ref)
        try:
            return self._view(session, detail)
        finally:
            detail.clear()

    def banner(self, session: Any, detail: dict[str, Any]) -> dict[str, Any]:
        """The detail pane's access info (no secrets)."""
        raw = access_policy.access_of(detail)
        unknown = access_policy.access_unknown(raw)
        rules = access_policy.effective(detail, access_policy.DEVICE_COMPUTER, access_policy.local_today())
        expires = raw.get("expires") if isinstance(raw, dict) and not unknown else ""
        return {"expired": rules["expired"], "expired_on": str(expires or "") if rules["expired"] else "",
                "unknown": unknown, "copy_once": rules["copy_once"]}

    def save(self, ref: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        allowed = {"copy", "phones", "expires", "reauth", "never_fill"}
        if not isinstance(changes, dict) or not set(changes) <= allowed:
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        for key in ("reauth", "never_fill"):
            if key in changes and type(changes[key]) is not bool:
                raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        session, lease = self._session_lease()
        detail = self._detail(session, ref)
        try:
            if detail.get("kind") not in CREDENTIAL_KINDS:
                raise ApiError("invalid", t("loginExtras.chooseALogin"))
            enforced = access_policy.enforced_policy(detail)
            raw = copy.deepcopy(access_policy.access_of(detail))
            policy = access_policy.normalized_policy(detail.get("policy"))
            revision = detail.get("revision")
        finally:
            detail.clear()
        unknown = access_policy.access_unknown(raw)
        base = {} if unknown or raw is None else dict(raw)
        wanted = {key: changes[key] for key in ("copy", "phones", "expires") if key in changes}
        if wanted:
            try:
                new_access = access_policy.clean_access({**base, **{k: ("" if v is None else v)
                                                                     for k, v in wanted.items()}})
            except (ValueError, TypeError):
                raise ApiError("invalid", t("access.expires")) from None
        else:
            new_access = raw
        new_policy = dict(policy)
        if "reauth" in changes:
            new_policy["require_master_password"] = changes["reauth"]
        if "never_fill" in changes:
            new_policy["fill"] = "never" if changes["never_fill"] else "click"
        tighter = (access_policy.tightens(raw, new_access) if wanted else False) or \
            (new_policy["require_master_password"] and not policy["require_master_password"]) or \
            (new_policy["fill"] == "never" and policy["fill"] != "never")
        if tighter:
            self._require_pro(session, "access_policies")
        # Any change to the rules of a login that is strict now (or by an expired/unknown rule) needs the
        # master password, never Windows Hello; other logins confirm it's the user (Hello allowed).
        strict = bool(enforced.get("require_master_password"))
        self._auth.reauthenticate(t("loginExtras.enterYourMasterPasswordTo7"), lease, allow_hello=not strict)
        self._require(lease)
        with self._lock:
            again = session.credential_detail(ref["id"]) or {}
            changed = again.get("revision") != revision
            again.clear()
            if changed:
                raise ApiError("changed", t("loginExtras.thisLoginSRulesChanged"))
            try:
                if wanted:
                    session.set_entry_access(ref["id"], new_access)
                if new_policy != policy:
                    self._extras._save_details(session, lease, ref["id"], policy=new_policy)
            except VaultError as exc:
                raise ApiError("invalid", str(exc)) from None
        revoke = getattr(self._controller.guard, "revoke_entry_grants", None)
        if callable(revoke):
            revoke(ref["id"])
        self._controller.touch()
        result = self.get(ref)
        result["message"] = t("access.saved")
        return result


# ------------------------------------------------------------------------------------- item history
_RULE_PATHS = ("scope.access", "policy")


def _touches_rules(path: str) -> bool:
    return any(path == rule or path.startswith(rule + ".") or rule.startswith(path + ".") for rule in _RULE_PATHS)


def _rule_flags(record: dict[str, Any], today: str) -> tuple[bool, ...]:
    """Each access rule as "on" (stricter) booleans, for comparing two versions of a login."""
    computer = access_policy.effective(record, access_policy.DEVICE_COMPUTER, today)
    phone = access_policy.effective(record, access_policy.DEVICE_PHONE, today)
    policy = access_policy.enforced_policy(record, today)
    return (computer["reauth"], not computer["autofill"], not phone["autofill"], computer["copy_once"],
            computer["phone_view"], computer["expired"], bool(policy.get("require_master_password")),
            policy.get("fill") == "never")


def rules_change(current: dict[str, Any], proposed: dict[str, Any]) -> tuple[bool, bool]:
    """``(loosens, tightens)``: does ``proposed`` turn any access rule off / on compared with ``current``."""
    today = access_policy.local_today()
    before, after = _rule_flags(current, today), _rule_flags(proposed, today)
    return any(b and not a for b, a in zip(before, after)), any(a and not b for b, a in zip(before, after))


# Key material a history diff never shows, even revealed: it has no use there (a passkey is used, not read).
_NEVER_REVEALED = {"passkey": ("payload.private_key",)}


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + ".")


def _never_revealed(kind: str, path: str) -> bool:
    return any(_under(path, prefix) for prefix in _NEVER_REVEALED.get(kind, ()))


def _master_hidden_changed(kind: str, rows: Iterable[dict[str, Any]]) -> bool:
    """Whether a typed item's diff touches a field that is shown only after the master password."""
    from .typed import MASTER_HIDDEN_FIELDS

    fields = MASTER_HIDDEN_FIELDS.get(kind, ())
    return any(_under(str(row["field"]), f"payload.{name}") for row in rows for name in fields)


class ItemHistoryService(_Base):
    """Device-local versions of logins (``entry_history``) and typed items (``HistoryService``)."""

    def _rows(self, session: Any, ns: str, item_id: str) -> list[dict[str, Any]]:
        if ns == "entry":
            return session.entry_history_rows(item_id)
        history = getattr(session, "history", None)
        if history is None:
            return []
        rows = []
        for row in history.list(item_id):
            rows.append({"snapshot_id": row["snapshot_id"], "created_at": int(row["created_at"]),
                         "change_type": str(row.get("change_type") or "update")})
        rows.sort(key=lambda r: (-r["created_at"], r["snapshot_id"]))
        return rows

    def _snapshot(self, session: Any, ns: str, item_id: str, snapshot_id: str) -> dict[str, Any]:
        if ns == "entry":
            for row in session.entry_history_rows(item_id):
                if row["snapshot_id"] == snapshot_id:
                    return row["record"]
        else:
            history = getattr(session, "history", None)
            if history is not None:
                from ..history import HistoryError

                try:
                    return history.snapshot(item_id, snapshot_id, reveal=True, intent="item history diff")
                except HistoryError:
                    pass
        raise ApiError("not_found", t("history.empty"))

    def list(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_lease()
        ns, current = _record(session, ref)
        rows = self._rows(session, ns, str(current["id"]))
        return {"rows": [{"snapshot_id": r["snapshot_id"], "created_at": int(r["created_at"]),
                          "change_type": str(r["change_type"])} for r in rows],
                "pro": self._pro(session, "item_history_long")}

    def diff(self, ref: dict[str, Any], snapshot_id: str, reveal: bool = False) -> dict[str, Any]:
        session, lease = self._session_lease()
        ns, current = _record(session, ref)
        kind = str(current.get("kind") or "")
        if reveal:
            # The same level as revealing the item normally: the master password for a strict login and for a
            # field that is shown only behind it (a secure note's body, ``typed.MASTER_HIDDEN_FIELDS``).
            if ns == "entry":
                strict = bool(access_policy.enforced_policy(current).get("require_master_password"))
            else:
                snapshot = self._snapshot(session, ns, str(current["id"]), snapshot_id)
                strict = _master_hidden_changed(kind, item_history.diff(snapshot, current, kind))
            title = "secrets.confirmToRevealThisNote" if kind == "note" else "secrets.confirmToRevealThisPassword"
            self._auth.reauthenticate(t(title), lease, allow_hello=not strict)
            self._require(lease)
            ns, current = _record(session, ref)
            kind = str(current.get("kind") or "")
        snapshot = self._snapshot(session, ns, str(current["id"]), snapshot_id)
        rows = item_history.diff(snapshot, current, kind, reveal=reveal)
        if reveal and ns != "entry" and _master_hidden_changed(kind, rows) and not strict:
            raise ApiError("changed", t("typed.err.changed"))
        for row in rows:
            if _never_revealed(kind, str(row["field"])):
                # Raw key material has no use in a diff: always masked (finding M2).
                row["before"] = None if row["before"] is None else item_history.MASK
                row["after"] = None if row["after"] is None else item_history.MASK
            row["restorable"] = item_history.restorable(row["field"])
        self._controller.touch()
        return {"fields": rows}

    @staticmethod
    def _proposed(current: dict[str, Any], snapshot: dict[str, Any], field: str) -> dict[str, Any]:
        try:
            return item_history.restore_field(current, snapshot, field, int(time.time()))
        except item_history.RestoreError as exc:
            key = "history.notRestorable" if exc.code == "not_restorable" else "history.invalidHere"
            raise ApiError(exc.code, t(key)) from None

    def restore_field(self, ref: dict[str, Any], snapshot_id: str, field: str) -> dict[str, Any]:
        session, lease = self._session_lease()
        strict = loosens = tightens = rules = False
        with self._lock:
            ns, current = _record(session, ref)
            snapshot = self._snapshot(session, ns, str(current["id"]), snapshot_id)
            proposed = self._proposed(current, snapshot, field)
            seen = item_history.canon(current)
            if ns == "entry":
                strict = bool(access_policy.enforced_policy(current).get("require_master_password"))
                rules = _touches_rules(str(field))
                loosens, tightens = rules_change(current, proposed)
        if tightens:
            # The same gate as the Access rules screen: setting or tightening a rule is Pro.
            self._require_pro(session, "access_policies")
        if strict or loosens:
            # Turning any rule off from history (fill never -> click, re-auth off, copy once off, an older
            # scope.access...) needs the same check as the Access rules screen: the master password when the
            # login is strict now, else confirm it's you (finding W-M3).  Asked outside the service lock, so other
            # history calls do not wait behind an open dialog; the record is checked again below (finding L9).
            self._auth.reauthenticate(t("loginExtras.enterYourMasterPasswordTo7"), lease, allow_hello=not strict)
            self._require(lease)
        with self._lock:
            ns, current = _record(session, ref)
            if item_history.canon(current) != seen:
                raise ApiError("changed", t("loginExtras.thisLoginSRulesChanged") if ns == "entry"
                               else t("typed.err.changed"))
            if ns == "entry" and access_policy.enforced_policy(current).get("require_master_password") and not strict:
                raise ApiError("changed", t("loginExtras.thisLoginSRulesChanged"))
            snapshot = self._snapshot(session, ns, str(current["id"]), snapshot_id)
            proposed = self._proposed(current, snapshot, field)
            rules = rules or loosens or tightens
            try:
                _replace(session, ns, current, proposed, "restore")
            except (VaultError, ValueError) as exc:
                raise ApiError("invalid_on_this_device", t("history.invalidHere")) from exc
        if rules:
            revoke = getattr(self._controller.guard, "revoke_entry_grants", None)
            if callable(revoke):
                revoke(str(ref.get("id")))
        self._controller.touch()
        return {"message": t("history.restored", field=field)}


# -------------------------------------------------------------------------------------- travel mode
def _travel_unhides(current: Any, new: Any) -> bool:
    """True when ``new`` drops any collection or tag that the active ``current`` setting hides."""
    if not travel.is_on(current):
        return False
    if not travel.is_on(new):
        return True
    def parts(setting: Any) -> tuple[set[str], set[str]]:
        cols = {str(c).strip().lower() for c in setting.get("collections") or [] if isinstance(c, str)}
        tags = {travel.fold(tag) for tag in setting.get("tags") or [] if isinstance(tag, str) and travel.fold(tag)}
        return cols, tags
    old_cols, old_tags = parts(current)
    new_cols, new_tags = parts(new)
    return not (old_cols <= new_cols and old_tags <= new_tags)


class TravelService(_Base):
    """Hide chosen collections and tags on this device (contract section 2)."""

    def get(self) -> dict[str, Any]:
        from .. import duress

        session, _lease = self._session_lease()
        if duress.is_decoy(session):
            return {"on": False, "collections": [], "tags": [], "hidden_count": 0, "available_collections": [],
                    "available_tags": [], "pro": False, "duress": True}
        setting = travel.setting_of(session) or {}
        on = travel.is_on(setting)
        collections = [{"id": str(c.get("id")), "name": str(c.get("name") or "")}
                       for c in session.collections.list() if isinstance(c, dict) and c.get("id")]
        tags: dict[str, str] = {}
        for summary in session.item_service.all_metadata_summaries():
            for tag in getattr(summary, "tags", ()) or ():
                tags.setdefault(travel.fold(tag), str(tag))
        return {"on": on, "collections": list(setting.get("collections") or []) if on else [],
                "tags": list(setting.get("tags") or []) if on else [],
                "hidden_count": len(travel.hidden_id_set(session)) if on else 0,
                "available_collections": sorted(collections, key=lambda c: c["name"].casefold()),
                "available_tags": sorted(tags.values(), key=str.casefold),
                "pro": self._pro(session, "travel"), "duress": False}

    def _refuse_duress(self, session: Any) -> None:
        from .. import duress

        if duress.is_decoy(session):
            raise ApiError("invalid", t("travel.needsPro"))

    def save(self, collections: Iterable[Any], tags: Iterable[Any]) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._refuse_duress(session)
        self._require_pro(session, "travel")
        try:
            setting = travel.clean_setting(True, collections, tags, since=int(time.time()))
        except (ValueError, TypeError) as exc:
            raise ApiError("invalid", str(exc)) from None
        if not setting.get("collections") and not setting.get("tags"):
            raise ApiError("invalid", t("travel.chooseCollections"))
        if _travel_unhides(travel.active_setting(session), setting):
            # Narrowing the hidden set shows items again, like turning it off: the master password, never Hello or
            # the grace (finding W-M2). Compared on the settings, not today's items, so a rule that hides nothing
            # today cannot be dropped silently either.
            self._auth.reauthenticate(t("travel.turnOffConfirm"), lease, allow_hello=False)
        self._require(lease)
        try:
            session._commit_prefs({travel.PREF_KEY: setting})
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        self._controller._bus.emit("items.changed", {})
        result = self.get()
        result["message"] = t("travel.saved")
        return result

    def off(self) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._refuse_duress(session)
        if travel.setting_of(session) is None:
            return {**self.get(), "message": t("travel.off")}
        # Turning it off shows hidden items again: the master password, never Hello or the grace (2.3).
        self._auth.reauthenticate(t("travel.turnOffConfirm"), lease, allow_hello=False)
        self._require(lease)
        try:
            session._commit_prefs({travel.PREF_KEY: None})
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        self._controller._bus.emit("items.changed", {})
        result = self.get()
        result["message"] = t("travel.off")
        return result


# ------------------------------------------------------------------------------------------ clean up
class HygieneService(_Base):
    """Duplicates, old and expired items; confirmed merges; bulk delete with one-level Undo (section 3)."""

    def __init__(self, controller: Any, port: Any) -> None:
        super().__init__(controller, port)
        self._journal: dict[str, Any] | None = None
        hooks = getattr(controller, "on_lock", None)
        if isinstance(hooks, list):
            hooks.append(self._forget)

    def _forget(self) -> None:
        self._journal = None

    @staticmethod
    def _records(session: Any) -> list[dict[str, Any]]:
        hidden = travel.hidden_id_set(session)
        rows = [r for r in _payload(session).get("entries", []) if isinstance(r, dict)]
        rows += [r for r in session._require_typed_catalog().get("items", []) if isinstance(r, dict)]
        return [r for r in rows if str(r.get("id")) not in hidden]

    def scan(self) -> dict[str, Any]:
        from .catalog import kind_label

        session, _lease = self._session_lease()
        records = self._records(session)
        by_id = {str(r.get("id")): r for r in records}
        found = hygiene.findings(records, int(time.time()), access_policy.local_today())
        groups = []
        for finding in found:
            items = []
            for item_id in finding["ids"]:
                rec = by_id[item_id]
                subtitle = str(rec.get("username") or "") if rec.get("kind") in CREDENTIAL_KINDS else ""
                items.append({"ref": _ref_of(rec), "title": _title(rec) or t("secrets.thisItem"),
                              "subtitle": subtitle or kind_label(str(rec.get("kind") or "")),
                              "updated_at": int(rec.get("updated_at") or 0)})
            groups.append({"type": finding["type"], "items": items})
        return {"summary": hygiene.summary(found), "groups": groups,
                "pro": self._pro(session, "hygiene_bulk"), "can_undo": self._journal is not None}

    @staticmethod
    def _refused(exc: hygiene.MergeRefused) -> ApiError:
        return ApiError("refused", t("hygiene.refused", reason=t(f"hygiene.reason.{exc.code}")))

    def _pair(self, session: Any, keeper_ref: dict[str, Any], other_ref: dict[str, Any]) -> tuple[Any, ...]:
        if str(keeper_ref.get("id")) == str(other_ref.get("id")):
            raise ApiError("refused", t("hygiene.refused", reason=t("hygiene.reason.not_mergeable")))
        ns, keeper = _record(session, keeper_ref)
        other_ns, other = _record(session, other_ref)
        hidden = travel.hidden_id_set(session)
        if str(keeper.get("id")) in hidden or str(other.get("id")) in hidden:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        if ns != other_ns or keeper.get("kind") != other.get("kind") or keeper.get("kind") == "desktop":
            raise ApiError("refused", t("hygiene.refused", reason=t("hygiene.reason.not_mergeable")))
        return ns, keeper, other

    def merge_preview(self, keeper_ref: dict[str, Any], other_ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_lease()
        _ns, keeper, other = self._pair(session, keeper_ref, other_ref)
        try:
            merged = hygiene.merge(keeper, other, int(time.time()))
        except hygiene.MergeRefused as exc:
            raise self._refused(exc) from None
        rows = item_history.diff(keeper, merged, str(keeper.get("kind") or ""))
        return {"fields": [{k: r[k] for k in ("field", "before", "after", "secret")} for r in rows]}

    def _merge_locked(self, session: Any, keeper_ref: dict[str, Any], other_ref: dict[str, Any],
                      journal: dict[str, Any] | None) -> None:
        ns, keeper, other = self._pair(session, keeper_ref, other_ref)
        try:
            merged = hygiene.merge(keeper, other, int(time.time()))
        except hygiene.MergeRefused as exc:
            raise self._refused(exc) from None
        before = copy.deepcopy(keeper)
        other_id = str(other.get("id"))
        with session.transaction():
            _replace(session, ns, keeper, merged, "merge")
            if ns == "entry":
                session.delete(other_id)
            else:
                session.item_service.delete_item(other_id)
        if journal is not None:
            _ns, now_keeper = _record(session, _ref_of(merged))
            after = item_history.canon(now_keeper)
            # A keeper merged more than once keeps its FIRST before-state: Undo restores what it was before the
            # bulk action, and the digest is the one the last merge wrote (finding W-L3).
            row = next((r for r in journal["merged"] if r["ns"] == ns and r["id"] == str(merged.get("id"))), None)
            if row is None:
                journal["merged"].append({"ns": ns, "id": str(merged.get("id")), "before": before, "after": after})
            else:
                row["after"] = after
            journal["trashed"].append({"ns": ns, "id": other_id})

    def merge(self, keeper_ref: dict[str, Any], other_ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._require(lease)
        with self._lock:
            try:
                self._merge_locked(session, keeper_ref, other_ref, None)
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        return {"message": t("hygiene.merged")}

    def merge_all(self) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._require_pro(session, "hygiene_bulk")
        found = hygiene.findings(self._records(session), int(time.time()), access_policy.local_today())
        groups = [f["ids"] for f in found if f["type"] == "same_login"]
        if not groups:
            return {"message": t("hygiene.none"), "count": 0}
        if not self._port.confirm(t("hygiene.mergeAll"), t("hygiene.mergeReview")):
            raise ApiError("cancelled", t("error.cancelled"))
        self._require(lease)
        journal: dict[str, Any] = {"merged": [], "trashed": []}
        count = 0
        with self._lock:
            for ids in groups:
                keeper_ref = {"source": "credential", "id": ids[0]}
                for other_id in ids[1:]:
                    try:
                        self._merge_locked(session, keeper_ref, {"source": "credential", "id": other_id}, journal)
                        count += 1
                    except (ApiError, VaultError):
                        continue
            self._journal = journal if count else self._journal
        self._controller.touch()
        return {"message": t("hygiene.mergedCount", count=count), "count": count}

    def delete(self, refs: list[dict[str, Any]]) -> dict[str, Any]:
        if not refs:
            raise ApiError("invalid", t("hygiene.none"))
        session, lease = self._session_lease()
        bulk = len(refs) > 1
        if bulk:
            self._require_pro(session, "hygiene_bulk")
        if not self._port.confirm(t("hygiene.delete"), t("hygiene.deleteSelected", count=len(refs))):
            raise ApiError("cancelled", t("error.cancelled"))
        self._require(lease)
        hidden = travel.hidden_id_set(session)
        journal: dict[str, Any] = {"merged": [], "trashed": []}
        with self._lock:
            try:
                with session.transaction():
                    for ref in refs:
                        ns, record = _record(session, ref)
                        item_id = str(record.get("id"))
                        if item_id in hidden:
                            continue
                        if ns == "entry":
                            session.delete(item_id)
                        else:
                            session.item_service.delete_item(item_id)
                        journal["trashed"].append({"ns": ns, "id": item_id})
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            if bulk:
                self._journal = journal
        self._controller.touch()
        return {"message": t("hygiene.deleted", count=len(journal["trashed"])), "can_undo": bulk}

    def undo(self) -> dict[str, Any]:
        session, lease = self._session_lease()
        self._require(lease)
        with self._lock:
            journal, self._journal = self._journal, None
            if journal is None:
                return {"message": t("hygiene.none")}
            for row in journal["trashed"]:
                try:
                    if row["ns"] == "entry":
                        session.restore_deleted(row["id"])
                    else:
                        session.item_service.restore_item(row["id"])
                except (VaultError, ValueError):
                    continue
            for row in journal["merged"]:
                try:
                    ns, current = _record(session, {"source": "credential" if row["ns"] == "entry" else "typed",
                                                    "id": row["id"]})
                except ApiError:
                    continue
                if item_history.canon(current) != row["after"]:
                    continue  # changed since the merge: kept as it is
                before = copy.deepcopy(row["before"])
                before["updated_at"] = int(time.time())
                try:
                    _replace(session, ns, current, before, "restore")
                except (VaultError, ValueError):
                    continue
        self._controller.touch()
        return {"message": t("hygiene.undone")}


__all__ = ["AccessRulesService", "HygieneService", "ItemHistoryService", "TravelService"]
