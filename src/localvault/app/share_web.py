"""Secure local sharing (UX workstream 9) for the WebView UI.

Send: the master password (never Windows Hello) seals one item into a ``.lgkshare`` package under a fresh
6-word code; the package is saved as a file or, when it fits, shown as a QR code. The code is only shown on
screen, never written next to the package.

Receive: an opened package is moved into the profile's private ``Incoming`` folder and the delivered copy is
deleted. The receiver types the code, sees a preview, then saves or rejects. Saving or rejecting deletes the
package; three wrong codes delete it; packages older than 24 hours are deleted. The ids of packages this
device opened are kept so the same package cannot be opened twice. Nothing secret is logged.
"""
from __future__ import annotations

import base64
import copy
import json
import logging
import os
import secrets
import socket
import time
import uuid
from pathlib import Path
from typing import Any

from .. import share
from ..api.result import ApiError
from ..i18n import t

_log = logging.getLogger(__name__)

SUFFIX = ".lgkshare"
MAX_WRONG = 3
OPENED_LIMIT = 500
CREDENTIAL_KINDS = ("web", "desktop")
NOT_SHAREABLE_KINDS = ("passkey", "document")
LABELS = {"username": "share.field.username", "password": "share.field.password", "notes": "share.field.notes",
          "url": "share.field.url", "totp": "share.field.totp", "exe_path": "share.field.exePath"}


def _sender_name() -> str:
    try:
        name = socket.gethostname().strip()
    except OSError:
        name = ""
    return (name or "A LocalGateKeys PC")[:share.SENDER_LIMIT]


def _label(key: str) -> str:
    return t(LABELS[key]) if key in LABELS else key.replace("_", " ").strip().capitalize() or key


def preview_fields(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Field rows for the receiver's preview: name, value, and whether the value starts masked."""
    from ..item_schema import PROTECTED_FIELDS_BY_KIND

    kind = str(item.get("kind") or "")
    rows: list[dict[str, Any]] = []
    if kind in CREDENTIAL_KINDS:
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
        target = scope.get("origin") or scope.get("exe_path") or ""
        if not target and isinstance(item.get("urls"), list) and item["urls"]:
            first = item["urls"][0]
            target = first.get("url", "") if isinstance(first, dict) else ""
        for key, value, secret in (("url" if kind == "web" else "exe_path", target, False),
                                   ("username", item.get("username"), False),
                                   ("password", item.get("password"), True),
                                   ("totp", (item.get("totp") or {}).get("secret") if isinstance(item.get("totp"), dict)
                                    else None, True),
                                   ("notes", item.get("notes"), False)):
            if isinstance(value, str) and value:
                rows.append({"name": _label(key), "value": value, "secret": secret})
        return rows
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else item.get("fields")
    protected = set(PROTECTED_FIELDS_BY_KIND.get(kind, ()))
    for key, value in (payload or {}).items() if isinstance(payload, dict) else ():
        if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value) != "":
            secret = key in protected or "password" in key or "secret" in key or "key" in key
            rows.append({"name": _label(str(key)), "value": str(value), "secret": secret})
    return rows


def _without_local_refs(item: dict[str, Any]) -> dict[str, Any]:
    """Drop what only means something in this vault: linked document ids and local trust approvals."""
    from ..transfer import LOCAL_TRUST_SCOPE_KEYS

    out = copy.deepcopy(item)
    payload = out.get("payload")
    if isinstance(payload, dict):
        if "document_ids" in payload:
            payload["document_ids"] = []
        if payload.get("billing_address_id"):
            payload["billing_address_id"] = ""
    scope = out.get("scope")
    if isinstance(scope, dict):
        for key in LOCAL_TRUST_SCOPE_KEYS:
            scope.pop(key, None)
    return out


def _outgoing(record: dict[str, Any]) -> dict[str, Any]:
    """The stored record as it travels (spec: the stored shape, minus local-only keys and references)."""
    return _without_local_refs(record)


def _incoming(item: dict[str, Any]) -> dict[str, Any]:
    """A received item in this vault's stored shape, keeping only the keys a new item may carry."""
    rec = _without_local_refs(share.stored_form(item))
    if rec.get("kind") not in CREDENTIAL_KINDS:
        rec = {k: v for k, v in rec.items() if k in ("id", "kind", "title", "created_at", "updated_at", "tags",
                                                     "payload")}
    else:
        rec.pop("revision", None)
    return rec


def _title(item: dict[str, Any]) -> str:
    return str(item.get("title") or item.get("label") or t("share.untitled"))


class ShareService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *, clock: Any = time.time) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._auth = SecretService(controller, port)
        self._clock = clock
        self._sealed: dict[str, dict[str, Any]] = {}  # handle -> {"data", "title"}; in memory only
        controller.on_lock.append(self._drop)

    def _drop(self) -> None:
        self._sealed.clear()

    # --------------------------------------------------------------- helpers
    def _session(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return controller.session, lease

    def _now(self) -> int:
        return int(self._clock())

    def _incoming_dir(self) -> Path:
        profiles = self._controller.profiles
        path = Path(profiles.profile_dir(profiles.ensure_profile().id)) / "Incoming"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _state_path(self) -> Path:
        return self._incoming_dir() / "state.json"

    def _state(self) -> dict[str, Any]:
        try:
            state = json.loads(self._state_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        state.setdefault("opened", [])
        state.setdefault("packages", {})
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        state["opened"] = [str(i) for i in state.get("opened", [])][-OPENED_LIMIT:]
        tmp = self._state_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._state_path())

    def _package_path(self, package_id: str) -> Path:
        try:
            clean = str(uuid.UUID(str(package_id)))
        except ValueError:
            raise ApiError("invalid", t("share.unknownSharedItem")) from None
        return self._incoming_dir() / f"{clean}{SUFFIX}"

    def _delete(self, state: dict[str, Any], package_id: str, *, opened: bool) -> None:
        try:
            self._package_path(package_id).unlink(missing_ok=True)
        except OSError:
            _log.warning("Could not delete a shared package")
        state["packages"].pop(package_id, None)
        if opened and package_id not in state["opened"]:
            state["opened"].append(package_id)

    def _expire(self, state: dict[str, Any]) -> None:
        now = self._now()
        for package_id, meta in list(state["packages"].items()):
            received = meta.get("received_at") if isinstance(meta, dict) else None
            if not isinstance(received, int) or now >= received + share.LIFETIME \
                    or not self._package_path(package_id).exists():
                self._delete(state, package_id, opened=False)

    # ------------------------------------------------------------------ send
    def start(self, ref: dict[str, Any]) -> dict[str, Any]:
        """Re-ask the master password, then seal the item. Returns the code and how it can travel."""
        session, lease = self._session()
        if ref.get("kind") in NOT_SHAREABLE_KINDS:
            raise ApiError("not_shareable", t("share.passkeysAndDocumentsWithFiles"))
        self._auth.reauthenticate(t("share.confirmToShareThisItem"), lease, allow_hello=False)
        self._controller.require_lease(lease)
        if ref["source"] == "credential":
            record = session.get_entry(ref["id"])
        else:
            record = session.item_service.get_item(ref["id"], include_protected=True)
        if not record:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        outgoing: dict[str, Any] = {}
        try:
            if record.get("kind") in NOT_SHAREABLE_KINDS:
                raise ApiError("not_shareable", t("share.passkeysAndDocumentsWithFiles"))
            code = share.generate_code()
            outgoing = _outgoing(record)
            try:
                data = share.seal(outgoing, code, sender=_sender_name(), now=self._now())
            except share.ShareError as exc:
                raise ApiError(exc.reason.replace("-", "_"), str(exc)) from None
            title = _title(record)
        finally:
            record.clear()
            outgoing.clear()
        handle = secrets.token_urlsafe(12)
        self._sealed = {handle: {"data": data, "title": title}}  # one pending share at a time
        return {"handle": handle, "code": code, "title": title, "size": len(data), "qr": share.fits_qr(data),
                "qr_limit": share.QR_LIMIT, "expires_hours": share.LIFETIME // 3600}

    def _sealed_for(self, handle: str) -> dict[str, Any]:
        entry = self._sealed.get(str(handle or ""))
        if entry is None:
            raise ApiError("stale", t("share.shareTheItemAgain"))
        return entry

    def save_file(self, handle: str) -> dict[str, Any]:
        entry = self._sealed_for(handle)
        safe = "".join(c for c in entry["title"] if c.isalnum() or c in " -_").strip()[:40] or "shared-item"
        chosen = self._dialogs.save_file(t("share.saveSharedItemLgkshare"), f"{safe}{SUFFIX}")
        if not chosen:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        path = Path(chosen)
        if path.suffix.lower() != SUFFIX:
            path = path.with_suffix(SUFFIX)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_bytes(entry["data"])
            os.replace(tmp, path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise ApiError("write_failed", t("share.theSharedItemCouldNot")) from None
        return {"path": str(path), "status": t("share.savedSendTheFileThen")}

    def qr(self, handle: str) -> dict[str, Any]:
        entry = self._sealed_for(handle)
        if not share.fits_qr(entry["data"]):
            raise ApiError("too_large", t("share.thisItemIsTooLarge"))
        import io

        import segno

        out = io.BytesIO()
        segno.make(entry["data"].decode("ascii"), error="l", micro=False, boost_error=False).save(
            out, kind="png", scale=4, border=4)
        return {"image": "data:image/png;base64," + base64.b64encode(out.getvalue()).decode("ascii")}

    def cancel(self) -> dict[str, Any]:
        self._drop()
        return {}

    # --------------------------------------------------------------- receive
    def _store(self, data: bytes, *, received_at: int | None = None) -> dict[str, Any]:
        try:
            header = share.read_header(data)
        except share.ShareError as exc:
            raise ApiError(exc.reason.replace("-", "_"), str(exc)) from None
        state = self._state()
        self._expire(state)
        if header["id"] in state["opened"]:
            raise ApiError("already_opened", t("share.thisSharedItemWasAlready"))
        target = self._package_path(header["id"])
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(bytes(data))
        os.replace(tmp, target)
        meta = state["packages"].get(header["id"])
        if not isinstance(meta, dict):
            meta = {"sender": header["sender"], "received_at": received_at or self._now(), "wrong": 0}
        state["packages"][header["id"]] = meta
        self._write_state(state)
        return {"id": header["id"], "sender": header["sender"]}

    def receive_file(self, path: str | None = None) -> dict[str, Any]:
        """Take a delivered ``.lgkshare`` into private storage and delete the delivered copy."""
        self._session()
        chosen = path or self._dialogs.open_file(t("share.openASharedItemLgkshare"))
        if not chosen:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        source = Path(chosen)
        try:
            if source.stat().st_size > share.MAX_PACKAGE:
                raise ApiError("malformed", t("share.thisIsNotAShared"))
            data = source.read_bytes()
        except OSError:
            raise ApiError("read_failed", t("share.theFileCouldNotBe")) from None
        stored = self._store(data)
        try:
            source.unlink()
        except OSError:
            _log.warning("Could not delete the delivered shared package")
        return {**stored, **self.incoming()}

    def receive_text(self, text: str) -> dict[str, Any]:
        """A package that came as a QR code (phones show one): its text, pasted or read from a snip."""
        self._session()
        raw = str(text or "").strip()
        if raw.startswith("lgkshare-code:"):
            raise ApiError("bad_code", t("share.thatIsTheCodeQr"))
        data = raw.encode("utf-8")
        if not raw.startswith("{") or len(data) > share.MAX_PACKAGE:
            raise ApiError("malformed", t("share.thisIsNotAShared"))
        stored = self._store(data)
        return {**stored, **self.incoming()}

    def receive_qr_image(self, data_url: str) -> dict[str, Any]:
        """A pasted snip (or picture) of the item's QR code; the image is decoded in memory and never saved."""
        from .qr_import import QrImportService, _load_cv, check_image, make_decoder

        self._session()
        raw = QrImportService._image_bytes(data_url)
        try:
            check_image(raw)
            cv2, np = _load_cv()
            image = cv2.imdecode(np.frombuffer(raw, dtype=np.uint8), getattr(cv2, "IMREAD_COLOR", 1))
            if image is None:
                raise ApiError("invalid", t("share.thatImageCouldNotBe"))
            texts = [t.strip() for t in make_decoder(cv2)(image)]
            del image
        finally:
            del raw
        package = next((t for t in texts if t.startswith("{") and share.FORMAT in t), None)
        if package is None:
            raise ApiError("not_found", t("share.noSharedLocalgatekeysItemWas"))
        return self.receive_text(package)

    def incoming(self) -> dict[str, Any]:
        self._session()
        state = self._state()
        self._expire(state)
        self._write_state(state)
        now = self._now()
        rows = [{"id": pid, "sender": str(meta.get("sender") or ""),
                 "hours_left": max(0, (int(meta["received_at"]) + share.LIFETIME - now + 3599) // 3600)}
                for pid, meta in sorted(state["packages"].items(), key=lambda kv: -int(kv[1]["received_at"]))]
        return {"incoming": rows}

    def _open(self, package_id: str, code: str) -> tuple[dict[str, Any], dict[str, Any]]:
        state = self._state()
        self._expire(state)
        if package_id not in state["packages"]:
            self._write_state(state)
            raise ApiError("gone", t("share.thisSharedItemIsNo"))
        data = self._package_path(package_id).read_bytes()
        try:
            opened = share.open_package(data, code, now=self._now(), opened=state["opened"])
        except share.ShareError as exc:
            code_name = exc.reason
            if code_name == "wrong-code":
                meta = state["packages"][package_id]
                meta["wrong"] = int(meta.get("wrong", 0)) + 1
                if meta["wrong"] >= MAX_WRONG:
                    # Burned: the same package delivered again is refused, so the count cannot be reset.
                    self._delete(state, package_id, opened=True)
                    self._write_state(state)
                    raise ApiError("deleted", t("share.threeWrongCodesTheShared")) from None
                self._write_state(state)
                left = MAX_WRONG - meta["wrong"]
                raise ApiError("wrong_code", t("share.wrongCodeTriesLeft", count=left)) from None
            if code_name in ("expired", "already-opened", "not-shareable", "unsupported"):
                self._delete(state, package_id, opened=False)
                self._write_state(state)
            raise ApiError(code_name.replace("-", "_"), str(exc)) from None
        except ValueError:
            raise ApiError("bad_code", t("share.typeTheSixWordsOf")) from None
        return opened, state

    def preview(self, package_id: str, code: str) -> dict[str, Any]:
        session, _lease = self._session()
        opened, _state = self._open(package_id, code)
        item = _incoming(opened["item"])
        opened["item"].clear()
        try:
            kind = str(item.get("kind") or "")
            duplicate = self._duplicate(session, item) is not None
            return {"id": package_id, "sender": opened["sender"], "kind": kind, "title": _title(item),
                    "fields": preview_fields(item), "duplicate": duplicate,
                    "passkey_warning": kind == "passkey"}
        finally:
            item.clear()

    @staticmethod
    def _duplicate(session: Any, item: dict[str, Any]) -> dict[str, Any] | None:
        if item.get("kind") != "web":
            return None
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
        origin, username = scope.get("origin"), item.get("username")
        if not isinstance(origin, str) or not isinstance(username, str):
            return None
        try:
            return session._web_login_match(origin, username)
        except Exception:
            return None

    def save(self, package_id: str, code: str, mode: str = "keep") -> dict[str, Any]:
        """Add the shared item (``keep`` both, or ``replace`` the matching login) and delete the package."""
        if mode not in ("keep", "replace"):
            raise ApiError("invalid", t("share.chooseReplaceOrKeepBoth"))
        session, lease = self._session()
        opened, state = self._open(package_id, code)
        item = _incoming(opened["item"])
        opened["item"].clear()
        try:
            self._controller.require_lease(lease)
            item["id"] = str(uuid.uuid4())
            now = self._now()
            item["created_at"] = item["updated_at"] = now
            item.pop("favorite", None)
            if item.get("kind") in CREDENTIAL_KINDS:
                self._add_credential(session, item, replace=self._duplicate(session, item) if mode == "replace"
                                     else None)
            elif item.get("kind") in NOT_SHAREABLE_KINDS:
                raise ApiError("not_shareable", t("share.passkeysAndDocumentsWithFiles"))
            else:
                self._add_typed(session, item)
        finally:
            item.clear()
        self._delete(state, package_id, opened=True)
        self._write_state(state)
        return {"status": t("share.savedToYourVault"), "changed": True}

    def _limit(self, exc: Exception) -> ApiError:
        limit = getattr(exc, "limit", None)
        try:
            self._port.show_upgrade(limit=limit, message=str(exc), on_enter=lambda: None)
        except Exception:
            _log.warning("Could not offer Pro for a shared item")
        return ApiError("item_limit", t("share.theFreePlanHoldsUp", limit=limit))

    def _add_credential(self, session: Any, item: dict[str, Any], *, replace: dict[str, Any] | None) -> None:
        from ..transfer import TransferError, _sanitize_credential, _validate_credential
        from ..vault import ItemLimitReached

        try:
            mapped = _validate_credential(_sanitize_credential(item))
        except TransferError:
            raise ApiError("invalid_item", t("share.thisSharedLoginCannotBe")) from None
        if replace is None:
            try:
                session._check_can_create()
            except ItemLimitReached as exc:
                raise self._limit(exc) from None
        payload = session._require_payload()
        original = copy.deepcopy(payload)
        try:
            entries = payload.setdefault("entries", [])
            if replace is not None:
                mapped["id"] = replace["id"]
                target = next((row for row in entries if row.get("id") == replace["id"]), None)
                if target is None:
                    entries.append(mapped)
                else:
                    target.clear()
                    target.update(mapped)
            else:
                entries.append(mapped)
            payload["updated_at"] = self._now()
            session.save()
        except BaseException:
            payload.clear()
            payload.update(original)
            raise
        finally:
            original.clear()

    def _add_typed(self, session: Any, item: dict[str, Any]) -> None:
        from ..item_schema import ItemSchemaError
        from ..vault import ItemLimitReached

        try:
            session.item_service._append(item)
        except ItemLimitReached as exc:
            raise self._limit(exc) from None
        except (ItemSchemaError, ValueError, TypeError):
            raise ApiError("invalid_item", t("share.thisSharedItemCannotBe")) from None

    def reject(self, package_id: str) -> dict[str, Any]:
        self._session()
        state = self._state()
        self._delete(state, str(package_id), opened=True)
        self._write_state(state)
        return {"status": t("share.theSharedItemWasDeleted"), **self.incoming()}
