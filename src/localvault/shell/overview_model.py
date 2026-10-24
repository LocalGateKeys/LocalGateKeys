"""Tk-free figures for the home screen's overview cards."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path


@dataclass(frozen=True)
class HealthOverview:
    score: int | None
    label: str
    weak: int
    reused: int
    no_2fa: int
    breached: int | None
    attention_ids: frozenset[str]
    no_2fa_ids: frozenset[str]


def health_overview(health: dict, breached_ids: set[str] | None = None) -> HealthOverview:
    weak = set(health.get("weak_ids", ()))
    reused = set(health.get("reused_ids", ()))
    no_2fa = frozenset(health.get("no_2fa_ids", ()))
    breached = set(breached_ids) if breached_ids is not None else None
    attention = frozenset(weak | reused | (breached or set()))
    total = int(health.get("total", 0))
    if total <= 0:
        score, label = None, "No logins yet"
    else:
        score = round(100 * (total - len(attention)) / total)
        label = "Good" if score >= 80 else "Fair" if score >= 50 else "Poor"
    return HealthOverview(score, label, len(weak), len(reused), len(no_2fa),
                          None if breached is None else len(breached), attention, no_2fa)


@dataclass(frozen=True)
class BackupStatus:
    last_at: float | None
    count: int
    warning: str


def backup_status(backup_dir: Path, warning: str = "") -> BackupStatus:
    try:
        mtimes = [p.stat().st_mtime for p in Path(backup_dir).glob("vault-*.json") if p.is_file()]
    except OSError:
        mtimes = []
    return BackupStatus(max(mtimes) if mtimes else None, len(mtimes), warning)


def _plural(n: int, unit: str) -> str:
    return f"{n} {unit}{'' if n == 1 else 's'}"


def age_text(seconds: float) -> str:
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{_plural(int(seconds // 60), 'minute')} ago"
    if seconds < 86400:
        return f"{_plural(int(seconds // 3600), 'hour')} ago"
    return f"{_plural(int(seconds // 86400), 'day')} ago"


@dataclass(frozen=True)
class ReminderLine:
    date_text: str
    label: str
    meta: str
    overdue: bool


def _as_date(value) -> date | None:
    """``value`` as a date, or None when it is missing or not an ISO date."""
    if isinstance(value, date):
        return value
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def upcoming_lines(rows: list[dict], today: date, limit: int = 3) -> list[ReminderLine]:
    """Rows are ReminderService rows: ISO or date ``due_date`` plus a ``label``.

    Rows without a usable ``due_date`` are skipped rather than failing the card.
    """
    pairs = ((_as_date(r.get("due_date")), r) for r in rows)
    dated = sorted(((due, r) for due, r in pairs if due is not None), key=lambda pair: pair[0])
    lines: list[ReminderLine] = []
    for due, row in dated[:limit]:
        days = (due - today).days
        meta = "overdue" if days < 0 else "today" if days == 0 else _plural(days, "day")
        lines.append(ReminderLine(f"{due.strftime('%b').upper()} {due.day}", str(row.get("label", "")), meta, days < 0))
    return lines
