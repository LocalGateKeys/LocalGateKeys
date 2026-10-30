"""Tk-free content of the Security center page: score, issues to fix and panels."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from ..i18n import t
from .overview_model import BackupStatus, age_text, health_overview

Tone = Literal["neutral", "accent", "success", "warning", "danger"]
STALE_BACKUP_SECONDS = 7 * 86400
_NAMES_SHOWN = 3


@dataclass(frozen=True)
class Action:
    """``getattr(app, method)(**dict(kwargs))`` — like a palette command."""

    label: str
    method: str
    kwargs: tuple[tuple[str, Any], ...] = ()
    primary: bool = False


@dataclass(frozen=True)
class Issue:
    key: str
    count: int
    title: str
    description: str
    tone: Tone
    action: Action


@dataclass(frozen=True)
class PanelRow:
    label: str
    meta: str
    action: Action
    meta_tone: Tone = "neutral"


@dataclass(frozen=True)
class Panel:
    title: str
    rows: tuple[PanelRow, ...]


@dataclass(frozen=True)
class UnlockMethods:
    """What the profile can unlock with; statuses only, never secrets."""

    hello_available: bool = False
    hello_enrolled: bool = False
    face_enrolled: bool | None = False
    recovery_phrase: bool | None = None


@dataclass(frozen=True)
class SecurityCenter:
    score: int | None
    label: str
    headline: str
    issues: tuple[Issue, ...]
    panels: tuple[Panel, ...]
    footnote: str


def _names(ids: list[str] | set[str], labels: dict[str, str]) -> str:
    names = sorted({labels.get(str(i), "") for i in ids} - {""}, key=str.casefold)
    if not names:
        return ""
    shown = names[:_NAMES_SHOWN]
    rest = len(names) - len(shown)
    text = ", ".join(shown)
    return t("security.namesAndMore", names=text, rest=rest) if rest else text


def _review(count: int, filter_key: str, label: str | None = None) -> Action:
    return Action(label or t("security.review", count=count), "password_health_clicked", (("initial_filter", filter_key),))


def _duration(seconds: int) -> str:
    from ..settings_ui import TIMEOUTS, display_duration

    return display_duration(int(seconds), dict(TIMEOUTS))


def lock_summary(settings: Any) -> str:
    """One line such as: After 15 minutes idle · when Windows locks · on sleep."""

    idle = int(getattr(settings, "auto_lock_seconds", 0) or 0)
    parts = [t("security.lock.afterIdle", duration=_duration(idle)) if idle else t("security.lock.noInactivity")]
    if getattr(settings, "lock_on_session_lock", False):
        parts.append(t("security.lock.whenWindowsLocks"))
    if getattr(settings, "lock_on_sleep", False):
        parts.append(t("security.lock.onSleep"))
    return " · ".join(parts)


def issues_for(health: dict, breached_ids: set[str] | None) -> tuple[Issue, ...]:
    labels = {str(row.get("id")): str(row.get("label") or "") for row in health.get("rows", ())}
    vault_ids = set(labels)
    out: list[Issue] = []
    if breached_ids is not None:
        breached = {str(i) for i in breached_ids} & vault_ids
        if breached:
            out.append(Issue(
                "breached", len(breached), t("security.issue.breached.title"),
                t("security.issue.breached.desc", names=_names(breached, labels)),
                "danger", _review(len(breached), "exposed", t("security.issue.breached.action"))))
    weak = [str(i) for i in health.get("weak_ids", ())]
    if weak:
        out.append(Issue("weak", len(weak), t("security.issue.weak.title"), _names(weak, labels), "warning",
                         _review(len(weak), "weak")))
    reused = [str(i) for i in health.get("reused_ids", ())]
    if reused:
        out.append(Issue("reused", len(reused), t("security.issue.reused.title"),
                         t("security.issue.reused.desc", names=_names(reused, labels)), "warning",
                         _review(len(reused), "reused")))
    no_2fa = [str(i) for i in health.get("no_2fa_ids", ())]
    if no_2fa:
        out.append(Issue("no_2fa", len(no_2fa), t("security.issue.no2fa.title"),
                         t("security.issue.no2fa.desc"), "accent",
                         _review(len(no_2fa), "no_2fa", t("security.issue.no2fa.action"))))
    old = [str(i) for i in health.get("old_ids", ())]
    if old:
        out.append(Issue("old", len(old), t("security.issue.old.title"),
                         t("security.issue.old.desc"), "neutral", _review(len(old), "old")))
    return tuple(out)


def headline_for(score: int | None, label: str, issues: tuple[Issue, ...]) -> str:
    if score is None:
        return t("security.headline.empty")
    scored = sum(i.count for i in issues if i.key in ("breached", "weak", "reused"))
    if score >= 100 or not scored:
        return t("security.headline.fine", label=label)
    return t("security.headline.fix", label=label)


def unlock_panel(methods: UnlockMethods, settings: Any) -> Panel:
    rows = [PanelRow(t("security.unlock.master.title"), t("security.unlock.master.desc"),
                     Action(t("security.btn.change"), "change_master_clicked"))]
    if methods.hello_available:
        rows.append(PanelRow(
            t("security.unlock.hello.title"), t("security.unlock.hello.on") if methods.hello_enrolled else t("security.notSetUp"),
            Action(t("security.btn.manage") if methods.hello_enrolled else t("security.btn.setUp"), "hello_settings_clicked",
                   primary=not methods.hello_enrolled)))
    face = methods.face_enrolled
    rows.append(PanelRow(
        t("security.unlock.camera.title"), t("security.unavailable") if face is None else (t("security.on") if face else t("security.notSetUp")),
        Action(t("security.btn.manage") if face else t("security.btn.setUp"), "face_settings_clicked")))
    phrase = methods.recovery_phrase
    rows.append(PanelRow(
        t("security.unlock.phrase.title"),
        t("security.unknown") if phrase is None else (t("security.unlock.phrase.set") if phrase else t("security.notSet")),
        Action(t("security.btn.manage") if phrase else t("security.btn.setUp"), "recovery_center_clicked",
               primary=phrase is False),
        "warning" if phrase is False else "neutral"))
    rows.append(PanelRow(t("security.unlock.autoLock.title"), lock_summary(settings),
                         Action(t("security.btn.edit"), "settings_clicked", (("section", "locking"),))))
    return Panel(t("security.panel.unlock"), tuple(rows))


def backup_panel(backup: BackupStatus, now: float) -> Panel:
    if backup.last_at is None:
        meta, tone = t("security.backup.none"), "warning"
    else:
        age = max(0.0, now - backup.last_at)
        copies = " · " + t("security.backup.copies", count=backup.count) if backup.count else ""
        meta = f"{age_text(age).capitalize()}{copies}"
        tone = "warning" if age > STALE_BACKUP_SECONDS else "neutral"
    if backup.warning:
        meta, tone = f"{meta} · {backup.warning}", "danger"
    return Panel(t("security.panel.backups"), (
        PanelRow(t("security.backup.last"), meta, Action(t("security.backup.now"), "recovery_center_clicked",
                                             (("allow_locked", True),), primary=True), tone),
        PanelRow(t("security.backup.check.title"), t("security.backup.check.desc"),
                 Action(t("security.backup.check.action"), "recovery_center_clicked", (("initial", "verify"),))),
        PanelRow(t("security.backup.restore.title"), t("security.backup.restore.desc"),
                 Action(t("security.backup.restore.action"), "recovery_center_clicked", (("initial", "restore"),))),
        PanelRow(t("security.backup.kit.title"), t("security.backup.kit.desc"),
                 Action(t("security.backup.kit.action"), "recovery_center_clicked", (("initial", "kit"),))),
    ))


def moving_panel() -> Panel:
    return Panel(t("security.panel.moving"), (
        PanelRow(t("security.moving.export.title"), t("security.moving.export.desc"),
                 Action(t("security.moving.export.action"), "export_clicked")),
        PanelRow(t("security.moving.transfer.title"), t("security.moving.transfer.desc"),
                 Action(t("security.btn.open"), "transfer_clicked")),
        PanelRow(t("security.moving.import.title"), t("security.moving.import.desc"), Action(t("security.moving.import.action"), "import_clicked")),
    ))


def privacy_panel(settings: Any) -> Panel:
    clip = int(getattr(settings, "clipboard_clear_seconds", 0) or 0)
    breach = bool(getattr(settings, "breach_check_enabled", False))
    offline = bool(getattr(settings, "strict_offline_mode", False))
    return Panel(t("security.panel.privacy"), (
        PanelRow(t("security.privacy.clipboard"), t("security.privacy.clipboardCleared", count=clip) if clip else t("security.privacy.clipboardNever"),
                 Action(t("security.btn.edit"), "settings_clicked", (("section", "privacy"),)), "neutral" if clip else "warning"),
        PanelRow(t("security.privacy.breach"), t("security.privacy.breachOn") if breach else t("security.off"),
                 Action(t("security.btn.turnOff") if breach else t("security.btn.turnOn"), "security_set_setting",
                        (("key", "breach_check_enabled"), ("value", not breach)))),
        PanelRow(t("security.privacy.offline.title"),
                 t("security.privacy.offline.on") if offline else t("security.privacy.offline.off"),
                 Action(t("security.btn.turnOff") if offline else t("security.btn.turnOn"), "security_set_setting",
                        (("key", "strict_offline_mode"), ("value", not offline)))),
    ))


def security_center(health: dict | None, breached_ids: set[str] | None, methods: UnlockMethods,
                    backup: BackupStatus, settings: Any, *, now: float | None = None) -> SecurityCenter:
    """Everything the Security center page shows, from already-computed, secret-free inputs."""

    now = time.time() if now is None else now
    health = health or {}
    vault_ids = {str(row.get("id")) for row in health.get("rows", ())}
    breached = None if breached_ids is None else {str(i) for i in breached_ids} & vault_ids
    overview = health_overview(health, breached)
    issues = issues_for(health, breached)
    return SecurityCenter(
        score=overview.score,
        label=overview.label,
        headline=headline_for(overview.score, overview.label, issues),
        issues=issues,
        panels=(unlock_panel(methods, settings), backup_panel(backup, now), moving_panel(),
                privacy_panel(settings)),
        footnote=t("security.footnote"),
    )
