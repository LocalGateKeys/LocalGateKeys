"""Login editor for the WebView UI: drafts live in Python, the page edits only safe fields.

The draft is ``shell.login_form.LoginDraft``; the page never receives the
password, the 2FA setup key, recovery codes or custom-field values. Saving uses
``session.create_web_login`` / ``session.save_login`` (with the edit token), the
path the Tk ``LoginEditor`` was built for.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from ..access_policy import normalized_policy
from ..api.result import ApiError
from ..password_tools import GeneratorOptions, generate_from_options, normalize_generator_options
from ..shell.login_form import (
    LoginDraft,
    UrlRow,
    draft_for_new_web,
    draft_from_detail,
    display_label,
    effective_label,
    password_meta,
    save_kwargs,
    snapshot,
    validate,
)
from ..totp import TotpError
from ..vault import (
    DuplicateLoginError,
    ItemLimitReached,
    LoginChangedError,
    ProFeatureRequired,
    VaultError,
)
from .licence_view import pro_required
from ..i18n import t

CHIPS = ("Passphrase", "Random", "PIN")
# The generator never makes passwords shorter than 8 characters, so a PIN is 8 digits.
PIN_LENGTH = 8
_EDITABLE = {"label", "urls", "username", "password", "favorite", "tags", "notes", "totp_text", "totp_remove",
             "policy"}


def _is_pin(options: GeneratorOptions) -> bool:
    return (options.mode == "password" and options.digits
            and not (options.lowercase or options.uppercase or options.symbols))


def options_for_chip(chip: str, current: GeneratorOptions) -> GeneratorOptions:
    """Generator options after choosing a mode chip; other preferences are kept."""
    if chip == "Passphrase":
        return replace(current, mode="passphrase")
    if chip == "PIN":
        return normalize_generator_options({
            **current.as_dict(), "mode": "password", "lowercase": False, "uppercase": False,
            "symbols": False, "digits": True, "avoid_ambiguous": False, "length": PIN_LENGTH,
            "min_digits": 1,
        })
    if chip != "Random":
        raise ValueError(t("loginEditor.unknownGeneratorChip", chip=chip))
    base = current
    if _is_pin(current):
        defaults = GeneratorOptions()
        base = replace(current, lowercase=defaults.lowercase, uppercase=defaults.uppercase,
                       digits=defaults.digits, symbols=defaults.symbols,
                       avoid_ambiguous=defaults.avoid_ambiguous, length=defaults.length)
    return replace(base, mode="password")


def chip_for(options: GeneratorOptions) -> str:
    if options.mode == "passphrase":
        return "Passphrase"
    return "PIN" if _is_pin(options) else "Random"


@dataclass
class _Open:
    draft: LoginDraft
    token: str | None
    original: tuple
    strength_key: bytes | None = None
    strength: dict[str, Any] | None = None


class LoginEditorService:
    def __init__(self, controller: Any, port: Any, *, generate: Callable[[], str]) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._generate = generate
        self._reauth = SecretService(controller, port)
        self._drafts: dict[str, _Open] = {}
        # pywebview calls arrive on worker threads and lock runs on the timer thread.
        self._lock = threading.RLock()
        controller.on_lock.append(self._drop_all)

    @staticmethod
    def _wipe(entry: _Open) -> None:
        entry.draft.password = None
        entry.draft.totp_text = ""
        entry.draft.notes = ""
        entry.draft.recovery_codes = []
        entry.draft.custom_fields = []
        entry.strength = None

    def _drop_all(self) -> None:
        with self._lock:
            for entry in self._drafts.values():
                self._wipe(entry)
            self._drafts.clear()

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    def _get(self, draft_id: str) -> _Open:
        with self._lock:
            entry = self._drafts.get(draft_id)
        if entry is None:
            raise ApiError("not_found", t("loginEditor.thisEditorWasClosedOpen"))
        return entry

    # ----------------------------------------------------------------- open
    def open_new(self) -> dict[str, Any]:
        self._session()
        draft = draft_for_new_web(self._generate())
        return self._register(draft, None)

    def open(self, ref: dict[str, Any]) -> dict[str, Any]:
        session = self._session()
        if ref.get("source") != "credential" or ref.get("kind") not in ("web", "desktop"):
            raise ApiError("unsupported", t("loginEditor.thisEditorEditsLogins"))
        lease = self._controller.guard.lease()
        # Read the token with the data it guards, before any prompt: a change made
        # while the prompt is open must make the later save fail with "changed".
        token = session.login_edit_token(ref["id"])
        detail = session.credential_detail(ref["id"])
        if detail is None:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        try:
            # Desktop logins have no URL rows; save_login keeps their app binding.
            urls = session.item_service.web_urls(ref["id"]) if detail.get("kind") == "web" else []
            draft = draft_from_detail(detail, urls)
            if normalized_policy(detail.get("policy")).get("require_master_password"):
                self._reauth.reauthenticate(t("loginExtras.openSensitiveCredential"), lease, allow_hello=False)
        finally:
            detail.clear()
        return self._register(draft, token)

    def _register(self, draft: LoginDraft, token: str | None) -> dict[str, Any]:
        draft_id = secrets.token_urlsafe(12)
        with self._lock:
            self._drafts[draft_id] = _Open(draft, token, snapshot(draft))
        return self.view(draft_id)

    # ---------------------------------------------------------------- edits
    def update(self, draft_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = self._get(draft_id)
            new_key = str(changes.get("totp_text") or "").strip()
            if new_key and new_key != entry.draft.totp_text and not self._totp_allowed():
                # Typed, scanned (QR) or picked from a Google Authenticator export:
                # the free plan says so now instead of at save.
                raise pro_required(self._port, ProFeatureRequired("totp"))
            self._apply(entry.draft, changes)
        return self.view(draft_id)

    @staticmethod
    def _apply(draft: LoginDraft, changes: dict[str, Any]) -> None:
        for key, value in changes.items():
            if key not in _EDITABLE:
                continue
            if key == "label":
                draft.label = str(value)
                draft.label_edited = bool(str(value).strip())
            elif key == "urls" and isinstance(value, list):
                draft.urls = [UrlRow(str(row.get("url", "")), str(row.get("match", "exact_origin")))
                              for row in value if isinstance(row, dict)]
            elif key == "username":
                draft.username = str(value)
            elif key == "password":
                draft.password = None if value is None else str(value)
            elif key == "favorite":
                draft.favorite = bool(value)
            elif key == "tags" and isinstance(value, list):
                draft.tags = [str(tag) for tag in value]
            elif key == "notes":
                draft.notes = str(value)
            elif key == "totp_text" and str(value).strip():
                draft.totp_text = str(value).strip()
            elif key == "totp_remove" and value:
                draft.totp_text = ""
            elif key == "policy" and isinstance(value, dict):
                draft.policy = normalized_policy({**draft.policy, **value})

    def regenerate(self, draft_id: str, chip: str) -> dict[str, Any]:
        entry = self._get(draft_id)
        settings = self._controller.settings
        options = options_for_chip(chip, normalize_generator_options(settings.generator_preferences))
        settings.generator_preferences = options.as_dict()
        try:
            settings.save()
        except Exception:  # noqa: BLE001, S110 - preferences are a convenience
            pass
        with self._lock:
            entry.draft.password = generate_from_options(options)
        return self.view(draft_id)

    def close(self, draft_id: str) -> None:
        with self._lock:
            entry = self._drafts.pop(draft_id, None)
        if entry is not None:
            self._wipe(entry)

    # ----------------------------------------------------------------- view
    def _reuse_count(self, password: str, entry_id: str | None) -> int:
        try:
            entries = self._controller.session.all_entries()
        except Exception:  # noqa: BLE001
            return 0
        try:
            return sum(1 for e in entries if e.get("password") == password and e.get("id") != entry_id)
        finally:
            for e in entries:
                e.clear()

    def view(self, draft_id: str) -> dict[str, Any]:
        entry = self._get(draft_id)
        draft = entry.draft
        strength = None
        if draft.password:
            # Strength and reuse need every login decrypted: compute once per password.
            key = hashlib.sha256(draft.password.encode("utf-8")).digest()
            if entry.strength_key != key:
                meta = password_meta(draft.password, reuse_count=self._reuse_count(draft.password, draft.entry_id))
                entry.strength = {"segments": meta.segments, "label": meta.label, "reuse_text": meta.reuse_text}
                entry.strength_key = key
            strength = entry.strength
        return {
            "draft_id": draft_id,
            "kind": draft.kind,
            "is_new": draft.entry_id is None,
            "label": draft.label if draft.label_edited else "",
            "label_hint": display_label(draft),
            "urls": [{"url": row.url, "match": row.match} for row in draft.urls],
            "app_path": draft.app_path,
            "username": draft.username,
            "password_set": draft.password is not None,
            "favorite": draft.favorite,
            "tags": list(draft.tags),
            "notes": draft.notes,
            "totp_configured": bool(draft.totp_text),
            # Free plan: an existing code stays (and can be removed); adding or changing one needs Pro.
            "totp_allowed": self._totp_allowed(),
            "policy": dict(draft.policy),
            "errors": [{"field": e.field, "message": e.message} for e in validate(draft)],
            "strength": strength,
            "dirty": snapshot(draft) != entry.original,
        }

    def _totp_allowed(self) -> bool:
        session = self._controller.session if self._controller.is_unlocked() else None
        allowed = getattr(session, "pro_features", None)
        return allowed is None or "totp" in allowed

    # ----------------------------------------------------------------- save
    def save(self, draft_id: str) -> dict[str, Any]:
        session = self._session()
        entry = self._get(draft_id)
        draft = entry.draft
        if validate(draft):
            raise ApiError("invalid", t("loginEditor.checkTheHighlightedFields"))
        lease = self._controller.guard.lease()
        if draft.entry_id is not None and not normalized_policy(draft.policy).get("require_master_password"):
            # Turning "always ask for the master password" off needs the master password now (no Windows Hello),
            # as in the login's rules sheet; the prompt at open does not count for it.
            stored = session.credential_detail(draft.entry_id)
            try:
                was_strict = stored is not None and bool(
                    normalized_policy(stored.get("policy")).get("require_master_password"))
            finally:
                if stored is not None:
                    stored.clear()
            if was_strict:
                self._reauth.reauthenticate(t("loginExtras.enterYourMasterPasswordTo7"), lease,
                                            allow_hello=False)
        try:
            kwargs = save_kwargs(draft)
        except (ValueError, TotpError) as exc:
            raise ApiError("invalid", str(exc)) from None
        self._controller.require_lease(lease)
        try:
            if draft.entry_id is None:
                urls = kwargs.pop("urls") or []
                entry_id = session.create_web_login(urls=urls, **kwargs)
            else:
                session.save_login(draft.entry_id, expected_token=entry.token or "", **kwargs)
                entry_id = draft.entry_id
        except DuplicateLoginError as exc:
            raise ApiError("duplicate", str(exc)) from None
        except LoginChangedError as exc:
            raise ApiError("changed", str(exc)) from None
        except ItemLimitReached as exc:
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            raise ApiError("item_limit", str(exc)) from None
        except ProFeatureRequired as exc:
            raise pro_required(self._port, exc) from None
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        finally:
            kwargs.clear()
        self._controller.touch()
        self.close(draft_id)
        return {"ref": {"source": "credential", "id": entry_id, "kind": draft.kind}}
