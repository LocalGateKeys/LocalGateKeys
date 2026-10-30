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
from ..i18n import t

# Catalog keys; the page texts are translated when a request is answered. The upper-case names stay
# readable (as English text) through the module ``__getattr__`` below.
_TEXT_KEYS = {
    "SUBTITLE": "health.subtitle", "FOOTER": "health.footer", "OFFLINE_TEXT": "health.offline",
    "DISABLED_TEXT": "health.disabled", "RUNNING_TEXT": "health.running", "ONE_TITLE": "health.oneTitle",
    "ONE_TEXT": "health.oneText", "ALL_TITLE": "health.allTitle",
}
FILTERS = (("health.filter.all", None), ("health.filter.weak", "weak"), ("health.filter.reused", "reused"),
           ("health.filter.no2fa", "no_2fa"), ("health.filter.old", "old"), ("health.filter.exposed", "exposed"))


def __getattr__(name: str) -> str:
    if name in _TEXT_KEYS:
        return t(_TEXT_KEYS[name])
    raise AttributeError(name)


JOB = "health"
SECONDS_PER_REQUEST = 1.5


def scan_all_text(unique: int, logins: int) -> str:
    seconds = unique * SECONDS_PER_REQUEST
    duration = (t("health.scanAll.underMinute") if seconds < 60
                else t("health.scanAll.aboutMinutes", count=round(seconds / 60)))
    return t("health.scanAll", unique=unique, logins=logins, seconds=f"{SECONDS_PER_REQUEST:g}", duration=duration,
             uniqueWord=t("health.password", count=unique), loginWord=t("health.login", count=logins))


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
            raise ApiError("locked", t("error.lockedProfile"))
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    # ---------------------------------------------------------------- report
    def report(self, filter: str | None = None) -> dict[str, Any]:  # noqa: A002 - the page's name
        from ..password_tools import vault_health

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
            state = self._exposure.get(str(row["id"]))
            if filter == "exposed" and not (state and state[0] == "found"):
                continue
            if filter not in (None, "exposed") and filter not in row["categories"]:
                continue
            rows.append({"id": str(row["id"]), "label": row["label"], "username": row["username"],
                         "score": row["score"], "categories": list(row["categories"]),
                         "findings": ", ".join(t(f"health.category.{c}") for c in row["categories"])
                         or t("health.noLocalFlag"),
                         "breach": self._breach_text(state), "breach_state": state[0] if state else "unchecked"})
        parts = [t("health.summary.logins", count=report["total"]), t("health.summary.weak", count=report["weak_count"]),
                 t("health.summary.reused", count=report["reused_count"]),
                 t("health.summary.no2fa", count=report["no_2fa_count"]),
                 t("health.summary.old", count=report["old_count"])]
        if self._exposure:
            exposed = sum(1 for state in self._exposure.values() if state[0] == "found")
            parts.append(t("health.summary.exposed", count=exposed))
        return {"summary": " · ".join(parts), "rows": rows, "subtitle": t("health.subtitle"),
                "footer": t("health.footer"),
                "filters": [{"label": t(label), "key": key} for label, key in FILTERS], "running": self._running}

    @staticmethod
    def _breach_text(state: tuple | None) -> str:
        """The row's breach result in words; ``state`` is ("found", n), ("clear",) or ("failed", note)."""
        if state is None:
            return t("health.breach.notChecked")
        if state[0] == "found":
            return t("health.breach.found", count=state[1], number=f"{state[1]:,}")
        if state[0] == "clear":
            return t("health.breach.notFound")
        return t("health.breach.failed", note=state[1])

    # ------------------------------------------------------------------ scan
    def scan(self, ids: list[str] | None) -> dict[str, Any]:
        from ..password_tools import breach_scan

        settings = self._controller.settings
        if settings.strict_offline_mode:
            raise ApiError("needs_setting", t("health.offline"), fix={"section": "privacy"})
        if not settings.breach_check_enabled:
            raise ApiError("needs_setting", t("health.disabled"), fix={
                "section": "privacy", "key": "breach_check_enabled", "value": True, "label": t("health.turnOnAndCheck")})
        with self._state_lock:
            if self._running:
                raise ApiError("refused", t("health.running"))
            self._running = True
            cancel = self._cancel = threading.Event()
        try:
            return self._start(ids, settings, cancel)
        except BaseException:
            with self._state_lock:
                self._running = False
            raise

    @staticmethod
    def _breach_passwords(session: Any, wanted: set[str]) -> dict[str, str]:
        """Passwords to check, by login id; a placeholder password (tag needs-password) is never sent."""
        from ..password_tools import needs_password

        entries = session.all_entries()
        passwords: dict[str, str] = {}
        try:
            for entry in entries:
                if str(entry.get("id")) in wanted and not needs_password(entry):
                    passwords[str(entry.get("id"))] = str(entry.get("password", ""))
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()
        return passwords

    @staticmethod
    def _unique_passwords(session: Any, wanted: set[str]) -> int:
        import hashlib

        from ..password_tools import needs_password

        entries = session.all_entries()
        digests: set[bytes] = set()
        try:
            for entry in entries:
                password = (str(entry.get("password", "")) if str(entry.get("id")) in wanted
                            and not needs_password(entry) else "")
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
            if not self._port.confirm(t("health.allTitle"), scan_all_text(unique, len(wanted))):
                raise ApiError("cancelled", t("error.cancelled"))
        else:
            wanted = {str(i) for i in ids}
            if len(wanted) != 1:
                raise ApiError("invalid", t("health.chooseOne"))
            if not self._port.confirm(t("health.oneTitle"), t("health.oneText")):
                raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        passwords = self._breach_passwords(session, wanted)
        total = len({p for p in passwords.values() if p})
        found: set[str] = set()
        results: dict[str, tuple] = {}
        done = {"count": 0}
        guard = self._controller.guard

        def stopped() -> bool:
            return cancel.is_set() or not guard.valid(lease)

        def report(entry_id: str, count: int | None, note: str) -> None:
            if stopped():
                return
            done["count"] += 1
            results[entry_id] = (("found", count) if count else ("clear",)) if count is not None else ("failed", note)
            if count:
                found.add(entry_id)
            self._bus.emit("job.progress", {"job": JOB, "text":
                                            t("health.progress", done=min(done["count"], total), total=total)})

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
                    self._bus.emit("job.done", {"job": JOB, "ok": False, "message": t("health.cancelled")})
                    return
                self._bus.emit("job.done", {"job": JOB, "ok": True, "message": (
                    t("health.done", checked=outcome["checked"], exposed=outcome["exposed"],
                      errors=outcome["errors"]))})
            except Exception as exc:  # noqa: BLE001 - surfaced to the user, never silently lost
                self._bus.emit("job.done", {"job": JOB, "ok": False,
                                            "message": str(exc) or t("health.failed")})
            finally:
                passwords.clear()
                results.clear()
                with self._state_lock:
                    self._running = False

        self._bus.emit("job.progress", {"job": JOB, "text": t("health.progressStart", total=total)})
        self._spawn(worker)
        return {"job": JOB}

    def cancel(self) -> dict[str, Any]:
        self._cancel.set()
        return {}
