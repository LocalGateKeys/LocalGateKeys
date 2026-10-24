"""Password health for the WebView UI, following ``FeatureUI.password_health_clicked``.

Local categories come from one decryption pass (no password kept). The HIBP
scan is opt-in per click, refused in strict offline mode, and runs on a
worker thread; progress reaches the page as ``job.progress`` / ``job.done``
events that carry counts only.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from ..api.result import ApiError

SUBTITLE = ("Local pattern checks are guidance, not a guarantee. Password age alone is not a reason to change it. "
            "Focus on reuse, guessability and known exposure.")
FOOTER = "No check is performed automatically. Passwords, hashes and results are not logged."
FILTERS = (("All", None), ("Weak", "weak"), ("Reused", "reused"), ("No 2FA", "no_2fa"),
           ("Old (>1 year)", "old"), ("Exposed (HIBP)", "exposed"))
OFFLINE_TEXT = "Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check."
DISABLED_TEXT = ("Breach checks are off. Turning them on lets a check button send a 5-character hash prefix to HIBP. "
                 "Nothing is checked automatically.")
RUNNING_TEXT = "Wait for the current breach check to finish."
ONE_TITLE = "Check selected password with HIBP?"
ONE_TEXT = ("Sends only a 5-character SHA-1 prefix over HTTPS with padding. The service sees your IP address. "
            "No password, full hash, username or website is sent.")
ALL_TITLE = "Check every password with HIBP?"
JOB = "health"
SECONDS_PER_REQUEST = 1.5


def scan_all_text(unique: int, logins: int) -> str:
    seconds = unique * SECONDS_PER_REQUEST
    duration = "under a minute" if seconds < 60 else f"about {round(seconds / 60)} minute{'s' if seconds >= 90 else ''}"
    return (f"Checks {unique} unique password{'s' if unique != 1 else ''} from {logins} login{'s' if logins != 1 else ''}, "
            f"one request about every {SECONDS_PER_REQUEST:g} seconds ({duration}). Each request sends only a "
            "5-character SHA-1 prefix over HTTPS. The service sees your IP address. No password, full hash, "
            "username or website is sent. You can keep using the app while it runs.")


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-hibp-scan").start()


class HealthService:
    def __init__(self, controller: Any, port: Any, home: Any, bus: Any, *, check: Callable[..., int] | None = None,
                 spawn: Callable[[Callable[[], None]], None] = _thread,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if check is None:
            from ..breach_check import check_password as check
        self._controller = controller
        self._port = port
        self._home = home
        self._bus = bus
        self._check = check
        self._spawn = spawn
        self._sleep = sleep
        self._exposure: dict[str, str] = {}
        self._running = False
        self._cancel = threading.Event()
        # Guards _running, the cancel event and the result commit against lock hooks
        # and concurrent js_api threads.
        self._state_lock = threading.RLock()
        controller.on_lock.append(self._on_lock)

    def _on_lock(self) -> None:
        with self._state_lock:
            self._cancel.set()
            self._exposure.clear()
            self._home.breached_ids = set()
            self._home._health_signature = None

    def _commit_guard(self, lease: Any) -> bool:
        """Called with _state_lock held: may this scan still publish its results?"""
        return not self._cancel.is_set() and self._controller.guard.valid(lease)

    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    # ---------------------------------------------------------------- report
    def report(self, filter: str | None = None) -> dict[str, Any]:  # noqa: A002 - the page's name
        from ..password_tools import HEALTH_CATEGORY_LABELS, vault_health

        session, _lease = self._session_lease()
        entries = session.all_entries()
        try:
            report = vault_health(entries)
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()
        rows = []
        for row in report["rows"]:
            breach = self._exposure.get(str(row["id"]), "Not checked")
            if filter == "exposed" and not breach.startswith("Found"):
                continue
            if filter not in (None, "exposed") and filter not in row["categories"]:
                continue
            rows.append({"id": str(row["id"]), "label": row["label"], "username": row["username"],
                         "score": row["score"], "categories": list(row["categories"]),
                         "findings": ", ".join(HEALTH_CATEGORY_LABELS[c] for c in row["categories"]) or "No local flag",
                         "breach": breach})
        parts = [f"{report['total']} logins", f"{report['weak_count']} weak", f"{report['reused_count']} reused",
                 f"{report['no_2fa_count']} without 2FA", f"{report['old_count']} older than a year"]
        if self._exposure:
            exposed = sum(1 for text in self._exposure.values() if text.startswith("Found"))
            parts.append(f"{exposed} exposed in breaches")
        return {"summary": " · ".join(parts), "rows": rows, "subtitle": SUBTITLE, "footer": FOOTER,
                "filters": [{"label": label, "key": key} for label, key in FILTERS], "running": self._running}

    # ------------------------------------------------------------------ scan
    def scan(self, ids: list[str] | None) -> dict[str, Any]:
        from ..password_tools import breach_scan

        settings = self._controller.settings
        if settings.strict_offline_mode:
            raise ApiError("needs_setting", OFFLINE_TEXT, fix={"section": "privacy"})
        if not settings.breach_check_enabled:
            raise ApiError("needs_setting", DISABLED_TEXT, fix={
                "section": "privacy", "key": "breach_check_enabled", "value": True, "label": "Turn on and check"})
        with self._state_lock:
            if self._running:
                raise ApiError("refused", RUNNING_TEXT)
            self._running = True
            cancel = self._cancel = threading.Event()
        try:
            return self._start(ids, settings, cancel)
        except BaseException:
            with self._state_lock:
                self._running = False
            raise

    @staticmethod
    def _unique_passwords(session: Any, wanted: set[str]) -> int:
        import hashlib

        entries = session.all_entries()
        digests: set[bytes] = set()
        try:
            for entry in entries:
                password = str(entry.get("password", "")) if str(entry.get("id")) in wanted else ""
                if password:
                    digests.add(hashlib.sha256(password.encode("utf-8")).digest())
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()
        return len(digests)

    def _start(self, ids: list[str] | None, settings: Any, cancel: threading.Event) -> dict[str, Any]:
        from ..password_tools import breach_scan

        session, lease = self._session_lease()
        replace = ids is None
        if replace:
            wanted = {str(getattr(s, "id", "")) for s in session.summaries()}
            # Count before asking, so the question says exactly how much will be sent and how long it takes.
            unique = self._unique_passwords(session, wanted)
            if not self._port.confirm(ALL_TITLE, scan_all_text(unique, len(wanted))):
                raise ApiError("cancelled", "Cancelled.")
        else:
            wanted = {str(i) for i in ids}
            if len(wanted) != 1:
                raise ApiError("invalid", "Choose one login.")
            if not self._port.confirm(ONE_TITLE, ONE_TEXT):
                raise ApiError("cancelled", "Cancelled.")
        self._controller.require_lease(lease)
        entries = session.all_entries()
        passwords: dict[str, str] = {}
        try:
            for entry in entries:
                if str(entry.get("id")) in wanted:
                    passwords[str(entry.get("id"))] = str(entry.get("password", ""))
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()
        total = len({p for p in passwords.values() if p})
        found: set[str] = set()
        results: dict[str, str] = {}
        done = {"count": 0}
        guard = self._controller.guard

        def stopped() -> bool:
            return cancel.is_set() or not guard.valid(lease)

        def report(entry_id: str, count: int | None, note: str) -> None:
            if stopped():
                return
            done["count"] += 1
            results[entry_id] = ((f"Found in {count:,} breaches" if count else "Not found") if count is not None
                                 else f"Check failed: {note}")
            if count:
                found.add(entry_id)
            self._bus.emit("job.progress", {"job": JOB, "text":
                                            f"Checking… {min(done['count'], total)} of {total} unique passwords"})

        def worker() -> None:
            try:
                outcome = breach_scan(passwords, check=self._check, sleep=self._sleep,
                                      strict_offline=settings.strict_offline_mode, cancelled=stopped, report=report)
                with self._state_lock:
                    committed = not outcome.get("cancelled") and self._commit_guard(lease)
                    if committed:
                        self._exposure.update(results)
                        self._home.breached_ids = set(found) if replace else set(self._home.breached_ids) | found
                        self._home._health_signature = None
                if not committed:
                    self._bus.emit("job.done", {"job": JOB, "ok": False, "message": "Breach check cancelled."})
                    return
                self._bus.emit("job.done", {"job": JOB, "ok": True, "message": (
                    f"Checked {outcome['checked']} unique passwords · {outcome['exposed']} logins exposed · "
                    f"{outcome['errors']} errors. Not found does not prove a password is safe.")})
            except Exception as exc:  # noqa: BLE001 - surfaced to the user, never silently lost
                self._bus.emit("job.done", {"job": JOB, "ok": False,
                                            "message": str(exc) or "The check failed or the session changed."})
            finally:
                passwords.clear()
                results.clear()
                with self._state_lock:
                    self._running = False

        self._bus.emit("job.progress", {"job": JOB, "text": f"Checking 0 of {total} unique passwords…"})
        self._spawn(worker)
        return {"job": JOB}

    def cancel(self) -> dict[str, Any]:
        self._cancel.set()
        return {}
