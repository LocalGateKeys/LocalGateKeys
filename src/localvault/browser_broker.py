"""Protocol v2: metadata first, explicit selected release, revocable session grants."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from .access_policy import may_sign_in, normalized_policy
from .app.ui_port import safe_confirm
from .bridge_status import record_warning
from .identity_fill import (
    CARD_FILL_LABELS,
    CARD_FILL_PROTOCOL,
    CARD_PROTECTED_TOKENS,
    IDENTITY_FIELDS,
    IDENTITY_FILL_PROTOCOL,
    CardReleaseManager,
    IdentityReleaseManager,
    card_fill_metadata,
    normalize_selected_card_fields,
    normalize_selected_fields,
    validate_identity_context,
)
from .origin import (
    MATCH_MODES,
    base_domain,
    canonicalize_origin,
    entry_urls,
    match_rank,
    matches,
    OriginError,
    _split_url,
    normalize_url,
    origin_of,
)
from .passkey_broker import PASSKEY_ACTIONS, PASSKEY_PROTOCOL, PasskeyBrokerMixin
from .session_guard import StaleSession
from .vault import ItemLimitReached, VaultError
from .version import APP_VERSION, PROTOCOL_VERSION


class BrowserBroker(PasskeyBrokerMixin):
    # Broker-issued gesture nonces: 16 random bytes (32 hex chars), single use,
    # bound to origin + browser context, expiring after GESTURE_NONCE_TTL seconds.
    GESTURE_NONCE_TTL = 30
    GESTURE_NONCE_MAX = 64
    # Requests that must prove continuity from a user gesture. "grant" actions
    # already hold a grant from a gestured begin_*; "gesture" actions are
    # stand-alone saves. Legacy ``user_gesture: true`` is honoured only while
    # settings.legacy_gesture_compat is true (off by default; the extension
    # always presents a nonce).
    _GESTURE_GATES = {"get_browser": "grant", "get_totp_browser": "grant",
                      "release_card_browser": "grant",
                      "save_browser": "gesture", "save_pending_browser": "gesture"}

    def dispatch_remote(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict): return {"ok": False, "error": "invalid_request"}
        stamp = self.guard.stamp()
        until = time.monotonic() + 90
        def run() -> dict[str, Any]:
            if self.guard.stamp() != stamp or time.monotonic() > until:
                return {"ok": False, "error": "session_changed"}
            action = request.get("action")
            if request.get("protocol") == PROTOCOL_VERSION:
                self.last_extension_seen = time.monotonic()
                self.last_extension_version = str(request.get("extension_version", "unknown"))[:30]
            if action == "ping":
                # Polling is NOT user activity and never extends a timeout, and
                # it is unauthenticated metadata: no lease, profile or settings.
                return {"ok": True, "version": APP_VERSION, "locked": not self._session_available()}
            if request.get("protocol") != PROTOCOL_VERSION:
                return {"ok": False, "error": "version_mismatch",
                        "message": "Update and reload both the extension and desktop app (protocol 2)."}
            self.last_extension_seen = time.monotonic()
            self.last_extension_version = str(request.get("extension_version", "unknown"))[:30]
            if not self.settings.browser_enabled:
                return {"ok": False, "error": "integration_disabled"}
            try:
                identity_action = isinstance(action, str) and action.endswith("_identity_browser")
                if identity_action and request.get("identity_protocol") != IDENTITY_FILL_PROTOCOL:
                    return {"ok": False, "error": "version_mismatch",
                            "message": "Update and reload the identity-fill extension."}
                card_action = isinstance(action, str) and action.endswith("_card_browser")
                if card_action and request.get("card_protocol") != CARD_FILL_PROTOCOL:
                    return {"ok": False, "error": "version_mismatch",
                            "message": "Update and reload the card-fill extension."}
                passkey_action = action in PASSKEY_ACTIONS
                if passkey_action and request.get("passkey_protocol") != PASSKEY_PROTOCOL:
                    return {"ok": False, "error": "version_mismatch",
                            "message": "Update and reload the passkey extension."}
                origin = canonicalize_origin(request.get("origin", ""))
                context = request.get("context", "")
                if not isinstance(context, str) or not 16 <= len(context) <= 8192:
                    raise ValueError("Missing browser document context")
                if identity_action or card_action or passkey_action:
                    # Identity and card release have a stricter, structured
                    # context than the legacy credential actions. The
                    # extension's sender metadata is the source of
                    # tab/document identity; direct callers must not
                    # substitute an arbitrary binding string.
                    validate_identity_context(context, origin)
                handlers = {"begin_browser": self._begin_browser, "get_browser": self._release_browser,
                            "begin_gesture_browser": self._begin_gesture_browser,
                            "validate_browser": self._validate_browser, "submit_browser": self._submit_browser,
                            "cancel_browser": self._cancel_browser, "check_browser": self._check_browser,
                            "save_browser": self._save_browser, "capture_browser": self._capture_browser,
                            "pending_browser": self._pending_browser, "save_pending_browser": self._save_pending_browser,
                            "discard_pending_browser": self._discard_pending_browser,
                            "clear_pending_browser": self._clear_pending_browser,
                            "begin_identity_browser": self._begin_identity_browser,
                            "approve_identity_browser": self._approve_identity_browser,
                            "release_identity_browser": self._release_identity_browser,
                            "cancel_identity_browser": self._cancel_identity_browser,
                            "begin_card_browser": self._begin_card_browser,
                            "approve_card_browser": self._approve_card_browser,
                            "release_card_browser": self._release_card_browser,
                            "cancel_card_browser": self._cancel_card_browser,
                            "begin_totp_browser": self._begin_totp_browser,
                            "get_totp_browser": self._release_totp_browser,
                            "passkey_create_browser": self._passkey_create_browser,
                            "passkey_get_browser": self._passkey_get_browser}
                handler = handlers.get(action)
                if handler is None: return {"ok": False, "error": "unsupported_action"}
                gate = self._GESTURE_GATES.get(action)
                if gate is not None:
                    denied = self._check_gesture(request, origin, context, grant_bound=gate == "grant")
                    if denied is not None: return denied
                interactive = action in {"begin_browser", "get_browser", "save_browser", "save_pending_browser",
                                         "begin_identity_browser", "approve_identity_browser",
                                         "release_identity_browser", "begin_card_browser",
                                         "approve_card_browser", "release_card_browser",
                                         "begin_totp_browser", "get_totp_browser",
                                         "passkey_create_browser", "passkey_get_browser"}
                if interactive and self._remote_busy:
                    return {"ok": False, "error": "busy", "message": "Finish the open LocalGateKeys prompt first."}
                if interactive: self._remote_busy = True
                try:
                    return handler(request, origin, context)
                finally:
                    if interactive: self._remote_busy = False
            except StaleSession:
                return {"ok": False, "error": "session_changed", "message": "Vault/profile changed or the request expired. Click Fill again."}
            except ItemLimitReached as exc:
                return self._item_limit_reply(exc.limit)
            except (ValueError, TypeError, VaultError):
                return {"ok": False, "error": "invalid_request", "message": "The operation could not be validated."}
        return self.run_on_ui(run, timeout=95)

    def _identity_release_manager(self) -> IdentityReleaseManager:
        manager = getattr(self, "_identity_release", None)
        if manager is None or manager.guard is not self.guard:
            manager = IdentityReleaseManager(self.guard)
            self._identity_release = manager
        return manager

    def _card_release_manager(self) -> CardReleaseManager:
        manager = getattr(self, "_card_release", None)
        if manager is None or manager.guard is not self.guard:
            manager = CardReleaseManager(self.guard)
            self._card_release = manager
        return manager

    @staticmethod
    def _page_url(request, origin: str) -> str:
        """Return the page URL used for multi-URL matching.

        The optional ``url`` must belong to the already-validated request
        origin; anything else fails closed as ``invalid_request``.  Without a
        ``url`` the origin itself is matched, which satisfies ``exact_origin``,
        ``host`` and ``base_domain`` rows but never a path-scoped
        ``starts_with`` row.
        """
        url = request.get("url")
        if url is None:
            return origin
        if not isinstance(url, str) or not url or len(url) > 4096:
            raise ValueError("Invalid page URL")
        if origin_of(url) != origin:
            raise ValueError("Page URL does not belong to the request origin")
        return normalize_url(url)

    def _session_available(self) -> bool:
        try:
            self.require_lease(self.guard.lease())
            return True
        except StaleSession:
            return False

    # -- gesture nonces -----------------------------------------------------
    def _gesture_store(self) -> dict[str, dict[str, Any]]:
        store = getattr(self, "_gesture_nonces", None)
        if store is None:
            store = {}
            self._gesture_nonces = store
        now = time.monotonic()
        for nonce, item in list(store.items()):
            if now - float(item["created"]) > self.GESTURE_NONCE_TTL:
                store.pop(nonce, None)
        return store

    def _issue_gesture_nonce(self, origin: str, context: str) -> str:
        store = self._gesture_store()
        while len(store) >= self.GESTURE_NONCE_MAX:
            store.pop(next(iter(store)))
        nonce = secrets.token_hex(16)
        store[nonce] = {"origin": origin, "context": context, "created": time.monotonic()}
        return nonce

    def _gesture_fields(self, origin: str, context: str) -> dict[str, Any]:
        return {"gesture_nonce": self._issue_gesture_nonce(origin, context),
                "gesture_expires_in": self.GESTURE_NONCE_TTL}

    def _legacy_gesture_compat(self) -> bool:
        # Fails closed: without the setting a request must carry a broker nonce.
        return getattr(self.settings, "legacy_gesture_compat", False) is True

    def _check_gesture(self, request, origin, context, *, grant_bound: bool) -> dict[str, Any] | None:
        """Return an error reply, or None when the request carries gesture proof.

        A presented nonce must exist, be unexpired and match this origin and
        browser context; it is consumed only on success, so a request from the
        wrong tab cannot burn a nonce the right tab still needs.
        """
        nonce = request.get("gesture_nonce")
        if nonce is not None:
            store = self._gesture_store()
            item = store.get(nonce) if isinstance(nonce, str) else None
            if item is None or item["origin"] != origin or item["context"] != context:
                return {"ok": False, "error": "gesture_nonce_invalid",
                        "message": "The gesture expired or belongs to another page. Click again."}
            store.pop(nonce, None)
            return None
        if not grant_bound and request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self._legacy_gesture_compat():
            return {"ok": False, "error": "gesture_nonce_required",
                    "message": "Update the browser extension: this action needs a fresh gesture nonce."}
        record_warning("legacy_gesture_compat_used")
        return None

    def _begin_gesture_browser(self, request, origin, context):
        """Mint a nonce for stand-alone save flows (no vault access, no lease)."""
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        return {"ok": True, **self._gesture_fields(origin, context)}

    def _begin_browser(self, request, origin, context):
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked(): return {"ok": False, "error": "user_cancelled"}
        page_url = self._page_url(request, origin)
        lease = self.guard.lease()
        choices = []
        # Candidates come from the login's URL rows (exact_origin / host /
        # base_domain / starts_with), ranked exact-origin first.  The service
        # strips passwords, history, TOTP and recovery codes before returning.
        for entry in self.session.items.find_web_candidates(page_url):
            policy = normalized_policy(entry.get("policy"))
            if policy["fill"] == "never":
                continue
            rank = match_rank(entry_urls(entry), page_url)
            if rank is None:
                continue
            choices.append({"entry_id": str(entry["id"]), "username": str(entry.get("username", "")),
                            "label": str(entry.get("label", "")), "favorite": bool(entry.get("favorite", False)),
                            "require_master_password": policy["require_master_password"],
                            "match": MATCH_MODES[rank]})
        choices.sort(key=lambda e: (MATCH_MODES.index(e["match"]), not e["favorite"],
                                    e["label"].casefold(), e["username"].casefold()))
        if not choices: return {"ok": False, "error": "not_found"}
        self.require_lease(lease)
        grant = self.guard.grant(origin, context, [e["entry_id"] for e in choices], kind="login")
        return {"ok": True, "choices": choices, "grant": grant, "origin": origin,
                "session_id": lease.token, "profile": {"name": self.active_profile.name, "color": self.active_profile.color},
                **self._gesture_fields(origin, context)}

    def _permission(self, request, origin, context, *, release=False, submit=False, kind="login"):
        # The grant kind is checked on every use: a 2FA grant never releases a
        # password (get_browser) and a login grant never releases a code.
        grant, entry_id = request.get("grant"), request.get("entry_id")
        if not isinstance(grant, str) or not isinstance(entry_id, str): raise StaleSession()
        lease = self.guard.permission(grant, origin, context, entry_id, release=release, submit=submit, kind=kind)
        self.require_lease(lease)
        return lease

    def _release_browser(self, request, origin, context):
        lease = self._permission(request, origin, context)
        page_url = self._page_url(request, origin)
        entry = self.session.get_entry(request["entry_id"])
        if not entry or entry["kind"] != "web" or not matches(entry_urls(entry), page_url):
            if entry: entry.clear()
            raise StaleSession()
        policy = normalized_policy(entry.get("policy"))
        if policy["fill"] == "never": return {"ok": False, "error": "fill_disabled"}
        if policy["require_master_password"] and not self.reauthenticate("Confirm master password for this credential", lease):
            return {"ok": False, "error": "user_cancelled"}
        self._permission(request, origin, context, release=True)
        username_only = request.get("username_only") is True
        if not entry.get("site_icon"):
            # Fill is a good moment to pick up icons for logins saved earlier.
            self._store_site_icon(entry["id"], request)
        credential = {"entry_id": entry["id"], "username": entry["username"], "origin": origin}
        if not username_only: credential["password"] = entry["password"]
        result = {"ok": True, "credential": credential,
                  "sign_in": not username_only and may_sign_in(entry, self.settings.fill_and_sign_in)}
        entry.clear()
        self._touch_secret()
        return result

    def _begin_totp_browser(self, request, origin, context):
        """List exact-origin logins that have 2FA; metadata only, no codes."""
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked(): return {"ok": False, "error": "user_cancelled"}
        lease = self.guard.lease()
        choices = []
        for summary in self.session.summaries():
            if summary.kind != "web" or summary.scope.get("origin") != origin: continue
            entry = self.session.get_entry(summary.id)
            try:
                totp = entry.get("totp")
                if not isinstance(totp, dict) or not totp.get("secret"): continue
                if normalized_policy(entry.get("policy"))["fill"] == "never": continue
                choices.append({"entry_id": summary.id, "username": summary.username, "label": summary.label,
                                "favorite": summary.favorite})
            finally:
                entry.clear()
        choices.sort(key=lambda e: (not e["favorite"], e["label"].casefold(), e["username"].casefold()))
        if not choices: return {"ok": False, "error": "totp_not_found"}
        self.require_lease(lease)
        grant = self.guard.grant(origin, context, [e["entry_id"] for e in choices], kind="totp")
        return {"ok": True, "choices": choices, "grant": grant, "origin": origin,
                "session_id": lease.token, "profile": {"name": self.active_profile.name, "color": self.active_profile.color},
                **self._gesture_fields(origin, context)}

    def _release_totp_browser(self, request, origin, context):
        """Release one code (plus the next one) for a one-time grant; never the secret.

        The secret is decoded once into a bytearray, both codes are derived from
        it, and the buffer is wiped before this method returns (also on error).
        The response and any error carry only the codes and remaining seconds;
        nothing on this path logs or echoes the secret or the entry's totp dict.
        """
        from .totp import (
            TotpError,
            decode_secret,
            generate_totp_from_key,
            requires_totp_confirmation,
            wipe,
        )
        lease = self._permission(request, origin, context, kind="totp")
        entry = self.session.get_entry(request["entry_id"])
        key = None
        try:
            if not entry or entry["kind"] != "web" or entry["scope"].get("origin") != origin:
                raise StaleSession()
            totp = entry.get("totp")
            if not isinstance(totp, dict) or not totp.get("secret"):
                return {"ok": False, "error": "totp_not_found"}
            policy = normalized_policy(entry.get("policy"))
            if policy["fill"] == "never": return {"ok": False, "error": "fill_disabled"}
            if policy["require_master_password"] and not self.reauthenticate("Confirm master password for this 2FA code", lease):
                return {"ok": False, "error": "user_cancelled"}
            if requires_totp_confirmation(self.settings):
                # Same trusted desktop prompt as identity/password-update
                # approvals: metadata only, never the secret or a code.
                approved = safe_confirm(self.ui, "Release 2FA code?",
                    f"Profile: {self.active_profile.name}\nOrigin: {origin}\n"
                    f"Login: {entry.get('username', '')}\n\n"
                    "One code will be typed into this page.",
                )
                self.require_lease(lease)
                if not approved:
                    return {"ok": False, "error": "user_cancelled"}
            try:
                key = decode_secret(totp["secret"])
                algorithm = str(totp.get("algorithm", "SHA1"))
                digits, period = int(totp.get("digits", 6)), int(totp.get("period", 30))
            except (TotpError, TypeError, ValueError):
                return {"ok": False, "error": "totp_not_found"}
            self._permission(request, origin, context, release=True, kind="totp")
            now = int(time.time())
            code, remaining = generate_totp_from_key(key, timestamp=now, digits=digits, period=period,
                                                     algorithm=algorithm, wipe_key=False)
            # The next code lets the page wait out a nearly expired one instead of failing.
            next_code, _ = generate_totp_from_key(key, timestamp=now + remaining, digits=digits, period=period,
                                                  algorithm=algorithm)
        finally:
            if key is not None: wipe(key)
            if entry: entry.clear()
        self._touch_secret()
        return {"ok": True, "code": code, "next_code": next_code, "remaining": remaining, "session_id": lease.token}

    def _begin_identity_browser(self, request, origin, context):
        """Return identity metadata only; no identity values leave the agent."""
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked():
            return {"ok": False, "error": "user_cancelled"}
        lease = self.guard.lease()
        choices = []
        for summary in self.session.item_service.metadata_summaries(kinds={"identity"}):
            view = self.session.item_service.identity_release_view(summary.id)
            choices.append({
                "entry_id": summary.id,
                "title": summary.title,
                "favorite": summary.favorite,
                "revision": view["revision"],
                "fields": sorted(field for field in view["fields"] if field in IDENTITY_FIELDS),
            })
        choices.sort(key=lambda item: (not item["favorite"], item["title"].casefold(), item["entry_id"]))
        if not choices:
            return {"ok": False, "error": "identity_not_found"}
        self.require_lease(lease)
        return {
            "ok": True,
            "identity_protocol": IDENTITY_FILL_PROTOCOL,
            "choices": choices,
            "origin": origin,
            "session_id": lease.token,
            "profile": {"name": self.active_profile.name, "color": self.active_profile.color},
        }

    def _identity_request(self, request, origin, context) -> tuple[Any, dict[str, Any], tuple[str, ...], Any]:
        entry_id = request.get("entry_id")
        revision = request.get("revision")
        if not isinstance(entry_id, str) or type(revision) is not int:
            raise StaleSession("The identity selection is malformed")
        fields = normalize_selected_fields(request.get("fields"))
        lease = self.guard.lease()
        view = self.session.item_service.identity_release_view(entry_id, expected_revision=revision)
        if set(fields) - set(view["fields"]):
            raise StaleSession("The selected identity fields changed")
        expected_session = request.get("session_id")
        if expected_session is not None and expected_session != lease.token:
            raise StaleSession("The identity session changed")
        return lease, view, fields, entry_id

    def _approve_identity_browser(self, request, origin, context):
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked():
            return {"ok": False, "error": "user_cancelled"}
        lease, view, fields, entry_id = self._identity_request(request, origin, context)
        lines = []
        for field in fields:
            # Values are shown only in trusted desktop review UI, never in
            # metadata, extension summaries, logs, or the approval response.
            value = str(view["fields"][field]).replace("\r", " ").replace("\n", " ")
            lines.append(f"{field}: {value}")
        approved = safe_confirm(self.ui, "Approve identity fill?",
            f"Profile: {self.active_profile.name}\nOrigin: {origin}\n\n"
            "Selected fields:\n" + "\n".join(lines) +
            "\n\nOnly these fields will be released once to this page.",
        )
        self.require_lease(lease)
        if not approved:
            return {"ok": False, "error": "user_cancelled"}
        token = self._identity_release_manager().issue(
            identity_id=entry_id, revision=view["revision"], origin=origin,
            context=context, fields=fields,
        )
        return {
            "ok": True,
            "identity_protocol": IDENTITY_FILL_PROTOCOL,
            "approval": token,
            "entry_id": entry_id,
            "revision": view["revision"],
            "fields": list(fields),
            "session_id": lease.token,
        }

    def _release_identity_browser(self, request, origin, context):
        token = request.get("approval")
        entry_id = request.get("entry_id")
        revision = request.get("revision")
        if not isinstance(token, str) or not isinstance(entry_id, str) or type(revision) is not int:
            return {"ok": False, "error": "invalid_request"}
        manager = self._identity_release_manager()

        def resolve() -> dict[str, Any]:
            return self.session.item_service.identity_release_view(
                entry_id, expected_revision=revision,
            )

        values = manager.release(
            token,
            identity_id=entry_id,
            revision=revision,
            origin=origin,
            context=context,
            fields=request.get("fields"),
            resolver=resolve,
        )
        self.guard.lease()  # still unlocked; the final reply carries no lease
        self._touch_secret()
        return {
            "ok": True,
            "identity_protocol": IDENTITY_FILL_PROTOCOL,
            "entry_id": entry_id,
            "revision": revision,
            "fields": list(values),
            "values": values,
        }

    def _cancel_identity_browser(self, request, origin, context):
        token = request.get("approval")
        if isinstance(token, str):
            self._identity_release_manager().revoke(token)
        return {"ok": True}

    # -- card fill (mirrors the identity flow) ------------------------------
    def _begin_card_browser(self, request, origin, context):
        """Return card metadata only; no number, CVV or PIN leaves the agent."""
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked():
            return {"ok": False, "error": "user_cancelled"}
        lease = self.guard.lease()
        choices = []
        items = self.session.item_service
        for summary in items.metadata_summaries(kinds={"card"}):
            view = items.card_fill_view(summary.id)
            try:
                metadata = card_fill_metadata(view)
            finally:
                view["fields"].clear()
            safe = items.get_item(summary.id) or {}
            payload = safe.get("payload", {}) if isinstance(safe.get("payload"), dict) else {}
            choices.append({
                "entry_id": summary.id,
                "title": summary.title,
                "favorite": summary.favorite,
                "revision": view["revision"],
                "brand": str(payload.get("brand", "")),
                "last4": str(payload.get("last4", "")),
                "fields": metadata,
            })
        choices.sort(key=lambda item: (not item["favorite"], item["title"].casefold(), item["entry_id"]))
        if not choices:
            return {"ok": False, "error": "card_not_found"}
        self.require_lease(lease)
        return {
            "ok": True,
            "card_protocol": CARD_FILL_PROTOCOL,
            "choices": choices,
            "origin": origin,
            "session_id": lease.token,
            "profile": {"name": self.active_profile.name, "color": self.active_profile.color},
            **self._gesture_fields(origin, context),
        }

    def _card_request(self, request, origin, context) -> tuple[Any, dict[str, Any], tuple[str, ...], Any]:
        entry_id = request.get("entry_id")
        revision = request.get("revision")
        if not isinstance(entry_id, str) or type(revision) is not int:
            raise StaleSession("The card selection is malformed")
        fields = normalize_selected_card_fields(request.get("fields"))
        lease = self.guard.lease()
        view = self.session.item_service.card_fill_view(entry_id, expected_revision=revision)
        if any(not view["fields"].get(field) for field in fields):
            raise StaleSession("The selected card fields changed")
        expected_session = request.get("session_id")
        if expected_session is not None and expected_session != lease.token:
            raise StaleSession("The card session changed")
        return lease, view, fields, entry_id

    @staticmethod
    def _card_review_line(field: str, value: str) -> str:
        """Render one review line; protected tokens are masked, never shown."""
        value = str(value).replace("\r", " ").replace("\n", " ")
        if field == "cc-number":
            value = "•••• " + value[-4:] if len(value) >= 4 else "••••"
        elif field in CARD_PROTECTED_TOKENS:
            value = "•" * max(3, min(len(value), 4))
        return f"{CARD_FILL_LABELS.get(field, field)}: {value}"

    def _approve_card_browser(self, request, origin, context):
        if request.get("user_gesture") is not True:
            return {"ok": False, "error": "user_gesture_required"}
        if not self.ensure_unlocked():
            return {"ok": False, "error": "user_cancelled"}
        lease, view, fields, entry_id = self._card_request(request, origin, context)
        try:
            lines = [self._card_review_line(field, view["fields"][field]) for field in fields]
        finally:
            view["fields"].clear()
        approved = safe_confirm(self.ui, "Approve card fill?",
            f"Profile: {self.active_profile.name}\nOrigin: {origin}\nCard: {view['title']}\n\n"
            "Selected fields:\n" + "\n".join(lines) +
            "\n\nOnly these fields will be released once to this page. The PIN is never released.",
        )
        self.require_lease(lease)
        if not approved:
            return {"ok": False, "error": "user_cancelled"}
        token = self._card_release_manager().issue(
            identity_id=entry_id, revision=view["revision"], origin=origin,
            context=context, fields=fields,
        )
        return {
            "ok": True,
            "card_protocol": CARD_FILL_PROTOCOL,
            "approval": token,
            "entry_id": entry_id,
            "revision": view["revision"],
            "fields": list(fields),
            "session_id": lease.token,
            **self._gesture_fields(origin, context),
        }

    def _release_card_browser(self, request, origin, context):
        # Gesture proof (nonce or legacy user_gesture) is checked by dispatch_remote.
        token = request.get("approval")
        entry_id = request.get("entry_id")
        revision = request.get("revision")
        if not isinstance(token, str) or not isinstance(entry_id, str) or type(revision) is not int:
            return {"ok": False, "error": "invalid_request"}
        manager = self._card_release_manager()

        def resolve() -> dict[str, Any]:
            return self.session.item_service.card_fill_view(entry_id, expected_revision=revision)

        values = manager.release(
            token,
            identity_id=entry_id,
            revision=revision,
            origin=origin,
            context=context,
            fields=request.get("fields"),
            resolver=resolve,
        )
        self.guard.lease()  # still unlocked; the final reply carries no lease
        self._touch_secret()
        return {
            "ok": True,
            "card_protocol": CARD_FILL_PROTOCOL,
            "entry_id": entry_id,
            "revision": revision,
            "fields": list(values),
            "values": values,
        }

    def _cancel_card_browser(self, request, origin, context):
        token = request.get("approval")
        if isinstance(token, str):
            self._card_release_manager().revoke(token)
        return {"ok": True}

    def _validate_browser(self, request, origin, context):
        self._permission(request, origin, context)
        return {"ok": True}

    def _submit_browser(self, request, origin, context):
        self._permission(request, origin, context, submit=True)
        entry = self.session.get_entry(request["entry_id"])
        if not entry or not may_sign_in(entry, self.settings.fill_and_sign_in):
            return {"ok": False, "error": "sign_in_disabled"}
        entry.clear()
        return {"ok": True, "submit": True}

    def _cancel_browser(self, request, origin, context):
        self.guard.revoke_grant(str(request.get("grant", "")))
        return {"ok": True}

    def _pending_store(self) -> dict[tuple[int, str], dict[str, Any]]:
        store = getattr(self, "_browser_pending_saves", None)
        if store is None:
            store = {}
            self._browser_pending_saves = store
        now = time.monotonic()
        for key, item in list(store.items()):
            if now - float(item.get("created", 0.0)) > 90.0:
                item["password"] = ""
                store.pop(key, None)
        return store

    @staticmethod
    def _browser_tab_id(context: str) -> int:
        try:
            value = json.loads(context)
            tab_id = value[0]
            if isinstance(tab_id, int) and tab_id >= 0:
                return tab_id
        except Exception:
            pass
        raise ValueError("Invalid browser tab context")

    @staticmethod
    def _browser_document_id(context: str) -> str:
        try:
            value = json.loads(context)
            document_id = value[1]
            if isinstance(document_id, str) and 1 <= len(document_id) <= 256:
                return document_id
        except Exception:
            pass
        raise ValueError("Invalid browser document context")

    PENDING_REDIRECT_GRACE = 12.0

    @staticmethod
    def _same_site(origin: str, other: str) -> bool:
        """Two different origins with the same scheme and port on one registrable domain (Public Suffix List).

        ``https://login.paddle.com`` and ``https://vendors.paddle.com`` are; two tenants of a shared
        hosting suffix (``a.github.io``, ``b.github.io``), IP addresses and other sites are not. Without
        a usable suffix list every host is its own base domain, so different hosts never match.
        """
        if origin == other:
            return False
        try:
            a_scheme, a_host, a_port, _, _ = _split_url(origin)
            b_scheme, b_host, b_port, _, _ = _split_url(other)
        except OriginError:
            return False
        if a_scheme != b_scheme or a_port != b_port:
            return False
        a_base = base_domain(a_host)
        return a_base == base_domain(b_host) and "." in a_base

    def _pending_for_context(self, origin: str, context: str) -> tuple[dict[str, Any] | None, tuple[int, str] | None]:
        """The pending capture this document may act on, and its store key.

        Its own origin's first; else, within the redirect grace, one from the same tab on
        another origin of the same site (a sign-in that lands on another subdomain). The
        capture keeps its own origin: that is where it is saved.
        """
        tab_id = self._browser_tab_id(context)
        document_id = self._browser_document_id(context)
        store = self._pending_store()
        key = (tab_id, origin)
        item = store.get(key)
        if item is None:
            now = time.monotonic()
            handoffs = [(k, v) for k, v in store.items()
                        if k[0] == tab_id and now - float(v.get("created", 0.0)) <= self.PENDING_REDIRECT_GRACE
                        and self._same_site(origin, k[1])]
            if not handoffs:
                return None, None
            key, item = max(handoffs, key=lambda kv: float(kv[1].get("created", 0.0)))
        if item.get("document_id") != document_id:
            # A redirect normally creates a new document. Allow a short grace
            # period for that transition, then erase the secret instead of
            # making it recoverable by any later same-origin document.
            if time.monotonic() - float(item.get("created", 0.0)) > self.PENDING_REDIRECT_GRACE:
                item["password"] = ""
                store.pop(key, None)
                return None, None
            item["document_id"] = document_id
        return item, key

    def _clear_pending_for_context(self, origin: str, context: str) -> None:
        try:
            key = (self._browser_tab_id(context), origin)
        except ValueError:
            return
        store = self._pending_store()
        item = store.pop(key, None)
        if item:
            item["password"] = ""

    def _capture_browser(self, request, origin, context):
        """Keep a submitted login in process RAM briefly so redirects cannot lose the save prompt.

        A locked vault cannot classify the submitted account yet.  Keep the
        candidate in the same bounded pending store, but make that state
        explicit so the extension does not present it as an already-classified
        new account before the user unlocks and the broker rechecks it.
        """
        username = self._validate_remote_text(request.get("username"), "username", 512, True)
        password = self._validate_remote_text(request.get("password"), "password", 4096, False)
        if not username:
            # A password-only step does not identify which account changed.
            # Fail closed so automatic save cannot create a nameless entry or
            # surface a misleading save prompt. Explicit manual save remains
            # available through save_browser, where the user can choose the
            # account name deliberately.
            password = ""
            return {"ok": True, "stored": False, "status": "username_required"}
        tab_id = self._browser_tab_id(context)
        status = "deferred"
        if self._session_available():
            if not self._probe_allowed(origin):
                password = ""
                return self._probe_limited()
            from .app.catalog import _classify_browser_submission
            entries = self.session.find_web(origin)
            result = _classify_browser_submission(entries, username, password)
            status = result["status"]
            prompt = all(normalized_policy(e.get("policy"))["save_prompts"] for e in entries if e["username"] == username)
            if result["match"]:
                # Signing in with an already-saved login is the moment to pick
                # up its site icon; no prompt is shown in that case.
                for entry in entries:
                    if entry.get("username") == username and not entry.get("site_icon"):
                        self._store_site_icon(entry["id"], request)
            for entry in entries:
                entry.clear()
            if result["match"] or not prompt:
                password = ""
                return {"ok": True, "stored": False, "status": status}
        token = secrets.token_urlsafe(24)
        store = self._pending_store()
        old = store.pop((tab_id, origin), None)
        if old:
            old["password"] = ""
        store[(tab_id, origin)] = {
            "token": token, "origin": origin, "username": username, "password": password,
            "status": status, "created": time.monotonic(),
            "document_id": self._browser_document_id(context),
        }
        return {"ok": True, "stored": True, "pending_token": token, "token": token, "status": status}

    def _pending_browser(self, request, origin, context):
        item, key = self._pending_for_context(origin, context)
        if not item:
            return {"ok": True, "pending": False}
        age_ms = max(0, int((time.monotonic() - float(item["created"])) * 1000))
        reply = {"ok": True, "pending": True, "pending_token": item["token"], "token": item["token"],
                 "status": item["status"], "age_ms": age_ms}
        if key[1] != origin:
            # A same-site handoff: this document is on another origin than the
            # one the login was typed on, and the broker cannot see whether the
            # browser really redirected from there. It learns only that a login
            # for that origin is waiting; the username is shown in the trusted
            # desktop confirmation, never to this page.
            reply["origin"] = key[1]  # the site it was typed on, where it is saved
            reply["handoff"] = True
        else:
            reply["username"] = item["username"]
        return reply

    def _discard_pending_browser(self, request, origin, context):
        item, key = self._pending_for_context(origin, context)
        store = self._pending_store()
        token = request.get("pending_token")
        if item and isinstance(token, str) and secrets.compare_digest(item["token"], token):
            item["password"] = ""
            store.pop(key, None)
        return {"ok": True}

    def _clear_pending_browser(self, request, origin, context):
        """Clear an automatic-save candidate when the page is logging out."""
        self._clear_pending_for_context(origin, context)
        return {"ok": True}

    def _submission_status(self, origin: str, username: str, password: str) -> str:
        """exact / password_changed / new for a submitted login, without keeping decrypted entries around."""
        from .app.catalog import _classify_browser_submission

        entries = self.session.find_web(origin)
        try:
            return _classify_browser_submission(entries, username, password)["status"]
        finally:
            for entry in entries:
                entry.clear()

    def _write_browser_save(self, origin: str, username: str, password: str,
                            request: dict[str, Any]) -> dict[str, Any] | str:
        """After the approval: classify again (another request may have saved meanwhile), then write.

        Returns the reply for an exact match or a full vault, else the status to report.
        """
        status = self._submission_status(origin, username, password)
        if status == "exact":
            return {"ok": True, "status": "existing"}
        if status != "password_changed":
            full = self._item_limit_full()
            if full is not None:
                return full
        entry_id = self.session.upsert_web(origin=origin, username=username, password=password)
        self._store_site_icon(entry_id, request)
        return "updated" if status == "password_changed" else "created"

    def _save_pending_browser(self, request, origin, context):
        # Gesture proof (nonce or legacy user_gesture) is checked by dispatch_remote.
        item, key = self._pending_for_context(origin, context)
        store = self._pending_store()
        token = request.get("pending_token")
        if not item or not isinstance(token, str) or not secrets.compare_digest(item["token"], token):
            return {"ok": False, "error": "session_changed"}
        # Saved for the origin it was typed on, also when the sign-in landed on
        # another subdomain of the same site; the confirmation names that origin.
        origin = key[1]
        if not self.ensure_unlocked():
            return {"ok": False, "error": "user_cancelled"}
        lease = self.guard.lease()
        username, password = item["username"], item["password"]
        status = self._submission_status(origin, username, password)
        if status == "exact":
            item["password"] = ""
            store.pop(key, None)
            return {"ok": True, "status": "existing"}
        updating = status == "password_changed"
        if not updating:
            full = self._item_limit_full()
            if full is not None:
                return full
        approved = self._confirm_browser_save(origin, username, updating=updating)
        self.require_lease(lease)
        if not approved:
            return {"ok": False, "error": "user_cancelled"}
        written = self._write_browser_save(origin, username, password, request)
        if isinstance(written, dict) and not written.get("ok"):
            return written  # the vault filled up meanwhile: keep the pending save for after an upgrade
        item["password"] = ""
        store.pop(key, None)
        if isinstance(written, dict):
            return written
        self.refresh_entries()
        self._touch_secret()
        return {"ok": True, "status": written}

    @staticmethod
    def _item_limit_reply(limit: int) -> dict[str, Any]:
        """Structured refusal for a new login on a full free vault (the extension shows ``message``)."""
        return {"ok": False, "error": "item_limit", "limit": int(limit),
                "message": f"Your free LocalGateKeys holds {int(limit)} items. Upgrade to Pro for unlimited."}

    def _item_limit_full(self) -> dict[str, Any] | None:
        """The item-limit reply when a new login cannot be added; checked before the desktop confirmation."""
        session = self.session
        limit = getattr(session, "item_limit", None)
        if limit is None:
            return None
        if session.live_item_count() >= limit:
            return self._item_limit_reply(limit)
        return None

    def _confirm_browser_save(self, origin: str, username: str, *, updating: bool) -> bool:
        """The trusted desktop confirmation for every browser save (SECURITY.md).

        The in-page Save button lives in a page the site controls (it can be
        imitated or clickjacked), so a new login is confirmed here with the
        canonical origin and username, exactly like a replaced password.
        """
        if updating:
            return bool(safe_confirm(self.ui, "Update password?",
                f"Profile: {self.active_profile.name}\nOrigin: {origin}\nUsername: {username}\n\n"
                "Replace the stored password? The previous password is kept in encrypted history."))
        return bool(safe_confirm(self.ui, "Save new login?",
            f"Profile: {self.active_profile.name}\nOrigin: {origin}\nUsername: {username or '(none)'}\n\n"
            "Save this login from the browser in LocalGateKeys?"))

    # -- password-guess oracle limits ---------------------------------------
    # check_browser / capture_browser compare a page-supplied password with
    # the stored one and need no gesture (they run on form submit), so bound
    # how often they answer: they must not become a guessing oracle.
    #
    # Limits are per origin and per registrable domain (one site with many
    # subdomains), so one site cannot use up the budget of the others. The
    # global cap is only a backstop against many sites at once, and even then
    # every site keeps a small reserved share (PROBE_RESERVE_PER_SITE) up to a
    # hard ceiling that bounds memory.
    PROBE_WINDOW = 60.0
    PROBE_LIMIT_PER_ORIGIN = 10
    PROBE_LIMIT_PER_SITE = 15
    PROBE_LIMIT_TOTAL = 60
    PROBE_RESERVE_PER_SITE = 3
    PROBE_HARD_LIMIT = 240

    @staticmethod
    def _probe_site(origin: str) -> str:
        """The registrable domain of an origin (scheme and port kept apart); the origin itself as a fallback."""
        try:
            scheme, host, port, _, _ = _split_url(origin)
            base = base_domain(host)
        except (OriginError, ValueError):
            return origin
        return f"{scheme}://{base}:{port}" if base and "." in base else origin

    def _probe_allowed(self, origin: str) -> bool:
        log = getattr(self, "_probe_log", None)
        if log is None:
            log = []
            self._probe_log = log
        now = time.monotonic()
        log[:] = [entry for entry in log if now - entry[0] < self.PROBE_WINDOW]
        site = self._probe_site(origin)
        same_origin = sum(1 for entry in log if entry[1] == origin)
        same_site = sum(1 for entry in log if entry[2] == site)
        if same_origin >= self.PROBE_LIMIT_PER_ORIGIN or same_site >= self.PROBE_LIMIT_PER_SITE:
            return False
        if len(log) >= self.PROBE_HARD_LIMIT:
            return False
        if len(log) >= self.PROBE_LIMIT_TOTAL and same_site >= self.PROBE_RESERVE_PER_SITE:
            return False
        log.append((now, origin, site))
        return True

    @staticmethod
    def _probe_limited() -> dict[str, Any]:
        return {"ok": False, "error": "rate_limited",
                "message": "Too many login checks from this site. Wait a minute and try again."}

    def _check_browser(self, request, origin, context):
        if not self._session_available(): return {"ok": True, "locked": True, "status": "locked", "match": False}
        if not self._probe_allowed(origin): return self._probe_limited()
        from .app.catalog import _classify_browser_submission
        username = self._validate_remote_text(request.get("username"), "username", 512, True)
        password = self._validate_remote_text(request.get("password"), "password", 4096, False)
        entries = self.session.find_web(origin)
        result = _classify_browser_submission(entries, username, password)
        show = all(normalized_policy(e.get("policy"))["save_prompts"] for e in entries if e["username"] == username)
        for entry in entries: entry.clear()
        return {"ok": True, "locked": False, "match": bool(result["match"]), "status": result["status"],
                "prompt": show}

    def _store_site_icon(self, entry_id, request) -> None:
        """Keep the page icon the extension read from the browser's own cache.

        Best effort: a missing or invalid icon never affects saving or filling.
        """
        encoded = request.get("site_icon")
        if not isinstance(encoded, str) or not encoded or len(encoded) > 90_000:
            return
        try:
            import base64

            from .site_icon import normalize_site_icon
            png = normalize_site_icon(base64.b64decode(encoded, validate=True))
            if self.session.set_entry_icon(entry_id, png) and hasattr(self, "refresh_entries"):
                self.refresh_entries()
        except Exception as exc:
            from .error_log import log_exception
            log_exception("site-icon", exc)

    def _save_browser(self, request, origin, context):
        # Gesture proof (nonce or legacy user_gesture) is checked by dispatch_remote.
        username = self._validate_remote_text(request.get("username"), "username", 512, True)
        password = self._validate_remote_text(request.get("password"), "password", 4096, False)
        # A stale page save banner may not silently unlock another person's vault.
        expected_session = request.get("session_id")
        if expected_session:
            lease = self.guard.lease()
            if lease.token != expected_session: raise StaleSession()
        if not self.ensure_unlocked(): return {"ok": False, "error": "user_cancelled"}
        lease = self.guard.lease()
        status = self._submission_status(origin, username, password)
        if status == "exact":
            self._clear_pending_for_context(origin, context)
            return {"ok": True, "status": "existing"}
        updating = status == "password_changed"
        if not updating:
            full = self._item_limit_full()
            if full is not None:
                return full
        approved = self._confirm_browser_save(origin, username, updating=updating)
        self.require_lease(lease)
        if not approved: return {"ok": False, "error": "user_cancelled"}
        written = self._write_browser_save(origin, username, password, request)
        if isinstance(written, dict) and not written.get("ok"):
            return written
        self._clear_pending_for_context(origin, context)
        if isinstance(written, dict):
            return written
        self.refresh_entries()
        self._touch_secret()
        return {"ok": True, "status": written}
