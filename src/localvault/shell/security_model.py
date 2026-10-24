"""Tk-free content of the Security center page: score, issues to fix and panels."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

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
    return f"{text} and {rest} more" if rest else text


def _review(count: int, filter_key: str, label: str | None = None) -> Action:
    return Action(label or f"Review {count}", "password_health_clicked", (("initial_filter", filter_key),))


def _duration(seconds: int) -> str:
    from ..settings_ui import TIMEOUTS, display_duration

    return display_duration(int(seconds), dict(TIMEOUTS))


def lock_summary(settings: Any) -> str:
    """One line such as: After 15 minutes idle · when Windows locks · on sleep."""

    idle = int(getattr(settings, "auto_lock_seconds", 0) or 0)
    parts = [f"After {_duration(idle)} idle" if idle else "No inactivity lock"]
    if getattr(settings, "lock_on_session_lock", False):
        parts.append("when Windows locks")
    if getattr(settings, "lock_on_sleep", False):
        parts.append("on sleep")
    return " · ".join(parts)


def issues_for(health: dict, breached_ids: set[str] | None) -> tuple[Issue, ...]:
    labels = {str(row.get("id")): str(row.get("label") or "") for row in health.get("rows", ())}
    vault_ids = set(labels)
    out: list[Issue] = []
    if breached_ids is not None:
        breached = {str(i) for i in breached_ids} & vault_ids
        if breached:
            out.append(Issue(
                "breached", len(breached), "Found in a data breach",
                f"{_names(breached, labels)} · these passwords appear in known breach lists",
                "danger", _review(len(breached), "exposed", "Change passwords")))
    weak = [str(i) for i in health.get("weak_ids", ())]
    if weak:
        out.append(Issue("weak", len(weak), "Weak passwords", _names(weak, labels), "warning",
                         _review(len(weak), "weak")))
    reused = [str(i) for i in health.get("reused_ids", ())]
    if reused:
        out.append(Issue("reused", len(reused), "Reused passwords",
                         f"{_names(reused, labels)} share a password with another login", "warning",
                         _review(len(reused), "reused")))
    no_2fa = [str(i) for i in health.get("no_2fa_ids", ())]
    if no_2fa:
        out.append(Issue("no_2fa", len(no_2fa), "Two-factor not set up",
                         "Add a one-time code to these logins where the site offers it", "accent",
                         _review(len(no_2fa), "no_2fa", "Set up 2FA")))
    old = [str(i) for i in health.get("old_ids", ())]
    if old:
        out.append(Issue("old", len(old), "Not changed in over a year",
                         "Low risk; change when convenient", "neutral", _review(len(old), "old")))
    return tuple(out)


def headline_for(score: int | None, label: str, issues: tuple[Issue, ...]) -> str:
    if score is None:
        return "Add logins to see how healthy your passwords are."
    scored = sum(i.count for i in issues if i.key in ("breached", "weak", "reused"))
    if score >= 100 or not scored:
        return f"{label} overall. Nothing urgent to fix."
    return f"{label} overall. Fixing the flagged logins below would bring you to 100."


def unlock_panel(methods: UnlockMethods, settings: Any) -> Panel:
    rows = [PanelRow("Master password", "Always works, even when other methods are off",
                     Action("Change…", "change_master_clicked"))]
    if methods.hello_available:
        rows.append(PanelRow(
            "Windows Hello", "On · fingerprint, face or PIN" if methods.hello_enrolled else "Not set up",
            Action("Manage" if methods.hello_enrolled else "Set up", "hello_settings_clicked",
                   primary=not methods.hello_enrolled)))
    face = methods.face_enrolled
    rows.append(PanelRow(
        "Camera check", "Unavailable" if face is None else ("On" if face else "Not set up"),
        Action("Manage" if face else "Set up", "face_settings_clicked")))
    phrase = methods.recovery_phrase
    rows.append(PanelRow(
        "Recovery phrase",
        "Unknown" if phrase is None else ("Set · unlocks if you forget the master password" if phrase else "Not set"),
        Action("Manage" if phrase else "Set up", "recovery_center_clicked", primary=phrase is False),
        "warning" if phrase is False else "neutral"))
    rows.append(PanelRow("Auto-lock", lock_summary(settings),
                         Action("Edit", "settings_clicked", (("section", "locking"),))))
    return Panel("How you unlock", tuple(rows))


def backup_panel(backup: BackupStatus, now: float) -> Panel:
    if backup.last_at is None:
        meta, tone = "No backup yet", "warning"
    else:
        age = max(0.0, now - backup.last_at)
        copies = f" · {backup.count} {'copy' if backup.count == 1 else 'copies'} kept" if backup.count else ""
        meta = f"{age_text(age).capitalize()}{copies}"
        tone = "warning" if age > STALE_BACKUP_SECONDS else "neutral"
    if backup.warning:
        meta, tone = f"{meta} · {backup.warning}", "danger"
    return Panel("Backups", (
        PanelRow("Last backup", meta, Action("Back up now", "recovery_center_clicked",
                                             (("allow_locked", True),), primary=True), tone),
        PanelRow("Check a backup", "Open it and confirm every item is there",
                 Action("Verify", "recovery_center_clicked", (("initial", "verify"),))),
        PanelRow("Restore from a backup", "Bring items back from a backup file",
                 Action("Restore…", "recovery_center_clicked", (("initial", "restore"),))),
        PanelRow("Recovery kit", "Printable sheet for when you forget everything",
                 Action("Write kit", "recovery_center_clicked", (("initial", "kit"),))),
    ))


MOVING_PANEL = Panel("Moving data", (
    PanelRow("Export vault", "Creates an unencrypted file; delete it when you are done",
             Action("Export…", "export_clicked")),
    PanelRow("Encrypted transfer", "Move items to another LocalGateKeys profile or PC",
             Action("Open", "transfer_clicked")),
    PanelRow("Import", "From another password manager or a file", Action("Import…", "import_clicked")),
))


def privacy_panel(settings: Any) -> Panel:
    clip = int(getattr(settings, "clipboard_clear_seconds", 0) or 0)
    breach = bool(getattr(settings, "breach_check_enabled", False))
    offline = bool(getattr(settings, "strict_offline_mode", False))
    return Panel("Privacy", (
        PanelRow("Clipboard", f"Cleared {clip} seconds after copying" if clip else "Never cleared automatically",
                 Action("Edit", "settings_clicked", (("section", "privacy"),)), "neutral" if clip else "warning"),
        PanelRow("Breach checks", "On · you start each check" if breach else "Off",
                 Action("Turn off" if breach else "Turn on", "security_set_setting",
                        (("key", "breach_check_enabled"), ("value", not breach)))),
        PanelRow("Strict offline mode",
                 "On · no background network access" if offline else "Off · no network access at all when on",
                 Action("Turn off" if offline else "Turn on", "security_set_setting",
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
        panels=(unlock_panel(methods, settings), backup_panel(backup, now), MOVING_PANEL,
                privacy_panel(settings)),
        footnote=("Breach checks send only the first 5 characters of a password hash, and only when you "
                  "start one. Strict offline mode blocks them."),
    )
