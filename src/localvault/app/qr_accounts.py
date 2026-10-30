"""2FA accounts read from a QR code in the Scan sheet, added to new or matching logins.

A scan (picture file, pasted snip or webcam; see ``qr_import``) hands the
decoded ``otpauth://`` or ``otpauth-migration://`` text here. The accounts and
their secrets stay in this process under a random token; the page only gets
issuer, account name and the logins that look like they belong to it.

* One key: the page opens a matching login (or a new one) in the login editor
  with the key applied, and the person saves it there.
* A Google Authenticator export: the page ticks accounts and adds them in one
  go. That goes through ``import_workflow`` (plan, review, atomic apply), so
  duplicates and the free plan's item limit are handled as file imports
  handle them. A multi-part export is merged code by code.

Two-factor codes are Pro: on the free plan every step shows the upgrade screen.
Secrets never reach the page, logs or error text.
"""
from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

from ..api.result import ApiError
from ..password_tools import NEEDS_PASSWORD_TAG
from ..totp import (
    TotpError,
    migration_match_score,
    normalize_secret,
    parse_migration_uri,
    parse_otpauth_uri,
)
from ..vault import ProFeatureRequired
from .licence_view import pro_required
from ..i18n import t

MAX_MATCHES = 5
MAX_CHOICES = 256
# Accounts kept per scan, across every part of a multi-part export.
MAX_SCAN_ACCOUNTS = 256
# Live scans kept at once; a new scan drops the oldest (a closed sheet discards its own).
MAX_LIVE_SCANS = 2
# Vault data (it syncs to other devices): always English, never translated.
NEEDS_PASSWORD_NOTE = ("Password not set — added from a 2FA QR code. "  # noqa: S105 - note text
                       "Replace this generated password with your real one.")
_SINGLE = "key"
_EXPORT = "export"


def _secret_of(totp: Any) -> str:
    if not isinstance(totp, dict):
        return ""
    try:
        return normalize_secret(str(totp.get("secret") or ""))
    except (TotpError, ValueError):
        return ""


def account_uri(account: dict[str, Any]) -> str:
    """The ``otpauth://`` link for one account (the editor and the importer read this form)."""
    query = urlencode({"secret": account["secret"], "issuer": account["issuer"], "digits": account["digits"],
                       "period": account["period"], "algorithm": account["algorithm"]})
    return f"otpauth://totp/{quote(str(account['label']))}?{query}"


def _wipe(scan: dict[str, Any]) -> None:
    for account in scan.get("accounts", []):
        account.clear()
    scan.clear()


class QrAccountsService:
    def __init__(self, controller: Any, editor: Any, port: Any, *, generate: Callable[[], str]) -> None:
        self._controller = controller
        self._editor = editor
        self._port = port
        self._generate = generate
        self._scans: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        controller.on_lock.append(self._drop_all)

    # ------------------------------------------------------------ helpers
    def _drop_all(self) -> None:
        with self._lock:
            for scan in self._scans.values():
                _wipe(scan)
            self._scans.clear()

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return self._controller.session

    def require_pro(self) -> None:
        """Free plan: show the upgrade screen, as the login editor does for a scanned key."""
        session = self._session()
        allowed = getattr(session, "pro_features", None)
        if allowed is not None and "totp" not in allowed:
            raise pro_required(self._port, ProFeatureRequired("totp"))

    def _scan(self, token: str) -> dict[str, Any]:
        with self._lock:
            scan = self._scans.get(str(token))
        if scan is None:
            raise ApiError("not_found", t("qrAccounts.thisScanWasClosedScan"))
        return scan

    def discard(self, token: str) -> dict[str, Any]:
        with self._lock:
            scan = self._scans.pop(str(token), None)
        if scan is not None:
            _wipe(scan)
        return {}

    # ------------------------------------------------------------ collect
    @staticmethod
    def _parse(text: str) -> dict[str, Any]:
        if text.lower().startswith("otpauth://"):
            try:
                parsed = parse_otpauth_uri(text)
            except TotpError as exc:
                raise ApiError("invalid", t("qrAccounts.thatQrCodeIsNot", exc=exc)) from None
            issuer = str(parsed.get("issuer") or "")
            label = str(parsed.get("label") or "")
            if not issuer and ":" in label:
                issuer, label = label.split(":", 1)
            elif issuer and label.startswith(issuer + ":"):
                label = label[len(issuer) + 1:]
            issuer = issuer.strip()
            account = {"secret": str(parsed["secret"]), "issuer": issuer, "label": label.strip(), "digits": int(parsed["digits"]),
                       "period": int(parsed["period"]), "algorithm": str(parsed["algorithm"])}
            return {"kind": _SINGLE, "accounts": [account], "skipped": [], "batch_index": 0, "batch_size": 1}
        try:
            found = parse_migration_uri(text)
        except TotpError as exc:
            raise ApiError("invalid", t("qrAccounts.thatGoogleAuthenticatorCodeCould", exc=exc)) from None
        return {"kind": _EXPORT, "accounts": list(found.get("accounts") or []),
                "skipped": [{"issuer": str(s.get("issuer") or ""), "label": str(s.get("label") or ""),
                             "reason": str(s.get("reason") or "")} for s in found.get("skipped") or []],
                "batch_index": int(found.get("batch_index") or 0), "batch_size": int(found.get("batch_size") or 1)}

    def collect(self, texts: list[str], token: str | None = None) -> dict[str, Any]:
        """Keep the accounts of a scanned code; with ``token``, add the next part of a multi-part export."""
        self.require_pro()
        if not texts:
            raise ApiError("not_found", t("qrAccounts.no2faQrCodeWas"))
        found = self._parse(texts[0])
        with self._lock:
            if token is None:
                scan = {"kind": found["kind"], "accounts": [], "skipped": [], "size": found["batch_size"],
                        "scanned": set()}
                token = secrets.token_urlsafe(12)
                while len(self._scans) >= MAX_LIVE_SCANS:
                    _wipe(self._scans.pop(next(iter(self._scans))))
            else:
                scan = self._scan(token)
                if found["kind"] != _EXPORT or scan["kind"] != _EXPORT or found["batch_size"] != scan["size"]:
                    for account in found["accounts"]:
                        account.clear()
                    raise ApiError("invalid", t("qrAccounts.thatCodeIsNotPart"))
            if (found["batch_index"] not in scan["scanned"]
                    and len(scan["accounts"]) + len(found["accounts"]) > MAX_SCAN_ACCOUNTS):
                for account in found["accounts"]:
                    account.clear()
                raise ApiError("invalid", t("qrAccounts.atMostAccountsCanBe", MAX_SCAN_ACCOUNTS=MAX_SCAN_ACCOUNTS))
            if found["batch_index"] in scan["scanned"]:
                for account in found["accounts"]:
                    account.clear()
            else:
                scan["scanned"].add(found["batch_index"])
                scan["accounts"].extend(found["accounts"])
                scan["skipped"].extend(found["skipped"])
            self._scans[token] = scan
        view = self.view(token)
        view["more_codes"] = max(0, len(texts) - 1)
        return view

    def view(self, token: str) -> dict[str, Any]:
        scan = self._scan(token)
        session = self._session()
        entries = session.all_entries()
        try:
            rows = []
            for index, account in enumerate(scan["accounts"]):
                ranked = sorted(
                    ((migration_match_score(account, str(e.get("label") or ""),
                                            str((e.get("scope") or {}).get("origin") or "")), n)
                     for n, e in enumerate(entries) if e.get("kind") == "web"),
                    reverse=True)
                matches = [entries[n] for score, n in ranked if score > 0][:MAX_MATCHES]
                # Picked by default only when unambiguous: exactly one login whose name is the issuer and whose
                # username is the account, both exactly (ignoring case). A substring match is only offered.
                issuer = str(account.get("issuer") or "").strip().casefold()
                name = str(account.get("label") or "").strip().casefold()
                exact = [e for e in entries if e.get("kind") == "web" and issuer and name
                         and str(e.get("label") or "").strip().casefold() == issuer
                         and str(e.get("username") or "").strip().casefold() == name]
                if len(exact) == 1 and all(m["id"] != exact[0]["id"] for m in matches):
                    matches = [exact[0], *matches][:MAX_MATCHES]
                secret = _secret_of(account)
                already = next((str(e.get("label") or "") for e in entries if secret and _secret_of(e.get("totp")) == secret),
                               None)
                rows.append({
                    "index": index, "issuer": str(account.get("issuer") or ""), "label": str(account.get("label") or ""),
                    "matches": [{"id": str(e["id"]), "label": str(e.get("label") or ""),
                                 "username": str(e.get("username") or ""),
                                 "website": str((e.get("scope") or {}).get("origin") or ""),
                                 "has_totp": bool(e.get("totp"))} for e in matches],
                    "best": str(exact[0]["id"]) if len(exact) == 1 else None,
                    "already": already,
                })
        finally:
            for e in entries:
                e.clear()
        missing = [i for i in range(scan["size"]) if i not in scan["scanned"]]
        return {"token": token, "kind": scan["kind"], "accounts": rows, "skipped": list(scan["skipped"]),
                "batch": {"size": scan["size"], "scanned": sorted(scan["scanned"]), "missing": missing},
                "complete": not missing}

    # --------------------------------------------------------------- one key
    def open(self, token: str, index: int, target_id: str | None) -> dict[str, Any]:
        """Open a login in the editor with the scanned key applied; the person saves it there."""
        self.require_pro()
        scan = self._scan(token)
        if not 0 <= index < len(scan["accounts"]):
            raise ApiError("invalid", t("loginExtras.chooseAnAccountFirst"))
        account = scan["accounts"][index]
        if target_id:
            entry = self._session().get_entry(str(target_id))
            kind = str(entry.get("kind")) if entry else ""
            if entry:
                entry.clear()
            if kind not in ("web", "desktop"):
                raise ApiError("not_found", t("qrAccounts.thatLoginNoLongerExists"))
            view = self._editor.open({"source": "credential", "id": str(target_id), "kind": kind})
            changes: dict[str, Any] = {"totp_text": account_uri(account)}
        else:
            view = self._editor.open_new()
            changes = {"totp_text": account_uri(account)}
            if account.get("issuer"):
                changes["label"] = str(account["issuer"])
            if account.get("label"):
                changes["username"] = str(account["label"])
        try:
            view = self._editor.update(view["draft_id"], changes)
        except BaseException:
            self._editor.close(view["draft_id"])
            raise
        finally:
            changes.clear()
        if scan["kind"] == _SINGLE:
            self.discard(token)
        return view

    # ------------------------------------------------------------ bulk add
    def _choices(self, scan: dict[str, Any], choices: Any, entries: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        from ..import_workflow import _web_url

        if not isinstance(choices, list) or not choices or len(choices) > MAX_CHOICES:
            raise ApiError("invalid", t("qrAccounts.tickAtLeastOneAccount"))
        out: list[dict[str, Any]] = []
        seen: set[int] = set()
        for choice in choices:
            if not isinstance(choice, dict):
                raise ApiError("invalid", t("qrAccounts.tickAtLeastOneAccount"))
            index = choice.get("index")
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(scan["accounts"]):
                raise ApiError("invalid", t("qrAccounts.thatAccountIsNotIn"))
            if index in seen:
                raise ApiError("invalid", t("qrAccounts.eachAccountCanBeAdded"))
            seen.add(index)
            account = scan["accounts"][index]
            name = str(account.get("issuer") or account.get("label") or f"account {index + 1}")
            target = str(choice.get("target") or "new")
            if target == "new":
                website, _upgraded = _web_url(str(choice.get("website") or "")[:2048])
                if not website:
                    raise ApiError("invalid", t("qrAccounts.typeTheWebsiteAddressFor", name=name))
                out.append({"index": index, "target": None, "website": website, "username": str(account.get("label") or "")})
                continue
            entry = entries.get(target)
            origin = str((entry or {}).get("scope", {}).get("origin") or "") if entry else ""
            if entry is None or entry.get("kind") != "web" or not origin:
                raise ApiError("invalid", t("qrAccounts.theLoginChosenForNo", name=name))
            if entry.get("totp") and choice.get("replace") is not True:
                raise ApiError("confirm_replace", t("qrAccounts.alreadyHasA2faCode", v1=entry.get('label') or 'The chosen login', name=name))
            out.append({"index": index, "target": target, "website": origin, "username": str(entry.get("username") or "")})
        # Keys for chosen logins first: a new login that repeats one of them is then the duplicate that is skipped.
        return sorted(out, key=lambda c: c["target"] is None)

    def add(self, token: str, choices: Any) -> dict[str, Any]:
        """Add the ticked export accounts in one go: new logins, or the key added to a chosen login."""
        from ..import_workflow import (
            ImportCancelled,
            ImportWorkflowError,
            item_limit_cause,
            plan_records,
        )
        from ..importers import ImportedRecord, ImporterError
        from ..vault import ItemLimitReached, VaultError

        self.require_pro()
        session = self._session()
        lease = self._controller.guard.lease()
        scan = self._scan(token)
        all_entries = session.all_entries()
        try:
            entries = {str(e.get("id")): e for e in all_entries}
            picked = self._choices(scan, choices, entries)
        finally:
            for e in all_entries:
                e.clear()
        records = []
        for number, choice in enumerate(picked, 1):
            account = scan["accounts"][choice["index"]]
            records.append(ImportedRecord(
                kind="login", title=str(account.get("issuer") or account.get("label") or "")[:200],
                username=choice["username"], password=self._generate(), urls=[choice["website"]],
                totp_uri=account_uri(account), source_row=number,
                # A new login's password is generated (the vault needs one): say so on the login itself.
                tags=[NEEDS_PASSWORD_TAG] if choice["target"] is None else [],
                notes=NEEDS_PASSWORD_NOTE if choice["target"] is None else ""))
        plan = None
        try:
            plan = plan_records(session, records)
            skipped: list[dict[str, str]] = []
            added = updated = 0
            for row, choice in zip(plan.rows, picked, strict=True):
                account = scan["accounts"][choice["index"]]
                who = {"issuer": str(account.get("issuer") or ""), "label": str(account.get("label") or "")}
                if row.kind != "login":
                    row.decision = "skip"
                    skipped.append({**who, "reason": t("qrAccounts.theWebsiteAddressIsNot")})
                elif choice["target"] is None:
                    if row.status != "new":
                        row.decision = "skip"
                        skipped.append({**who, "reason": t("qrAccounts.aLoginForThisWebsite")})
                    else:
                        added += 1
                elif row.target_id != choice["target"] or row.in_import_duplicate:
                    row.decision = "skip"
                    skipped.append({**who, "reason": t("qrAccounts.thatLoginWasAlreadyChosen")})
                else:
                    plan.set_decision(row, "merge", fields={"label": "keep", "password": "keep", "details": "import"})
                    updated += 1
            plan.recompute_limits()
            limited = plan.summary()["limited"]
            if limited:
                self._port.show_upgrade(limit=plan.item_limit, message=plan.limit_note(), on_enter=lambda: None)
                raise ApiError("item_limit", plan.limit_note() or t("importExport.theFreePlanIsFull"))
            if not added and not updated:
                return {"added": 0, "updated": 0, "skipped": skipped,
                        "message": t("qrAccounts.nothingWasAddedEveryTicked")}
            self._controller.require_lease(lease)
            plan.review()
            plan.apply(session)
        except ApiError:
            raise
        except ImportCancelled:
            raise ApiError("cancelled", t("qrAccounts.cancelledNothingWasWritten")) from None
        except (ImportWorkflowError, ImporterError, VaultError, ValueError) as exc:
            limit = item_limit_cause(exc)
            if limit is not None or isinstance(exc, ItemLimitReached):
                limit = limit or exc
                self._port.show_upgrade(limit=limit.limit, message=str(limit), on_enter=lambda: None)
                raise ApiError("item_limit", str(limit)) from None
            raise ApiError("vault_error", t("qrAccounts.theAccountsCouldNotBe")) from None
        finally:
            if plan is not None:
                plan.wipe()
            for record in records:
                record.wipe()
        self.discard(token)
        self._controller.touch()
        parts = []
        if added:
            parts.append(t("qrAccounts.newLoginsWith2fa", count=added))
        if updated:
            parts.append(t("qrAccounts.codeAddedToLogins", count=updated))
        message = t("qrAccounts.added", list=t("common.listAnd").join(parts)) if parts else ""
        if added:
            message += " " + t("qrAccounts.newLoginsNote")
        return {"added": added, "updated": updated, "skipped": skipped, "message": message}
