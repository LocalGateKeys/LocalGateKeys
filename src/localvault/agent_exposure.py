"""Which logins and secrets an AI agent has seen, derived on this device from the logs (never stored in the vault).

A login is exposed when an agent's approved password fill released its password into a page (activity event
``agent.fill`` / ``ok`` with the login's id, written when the page receives the password the user picked) and its
password has not changed since: no ``password_history`` row has a ``changed_at`` after the fill.

A secret item (API key, SSH key, note) is exposed when ``run_with_secrets`` released one of its fields to a command
(``agent.read`` / ``ok`` with the item's id) and the item has not been saved since: its ``updated_at`` is not after
the release (a save in the same second counts as before it). Typed items keep no per-field change time, so any
save of the item (a rename too) clears it.

Passkey sign-ins, denied, refused and expired requests are logged without an item id or with another result, so
they never count; neither do older fill events, which had no item id. The agent's name comes from the device-only
run log (``agent_run_log``: a ``filled`` or ``released`` row for the item close to the event); without one the
page shows a generic name.

Dismissals are device-only (``settings.agent_exposure_dismissed``, entries ``"<item id>@<unix time>"``): an
exposure at or before the dismissal time is hidden; a later release shows the item again.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

LOGIN_EVENT = "agent.fill"
SECRET_EVENT = "agent.read"  # noqa: S105 - an event name, not a secret
NAME_WINDOW = 600  # seconds between the activity event and its run-log row
RUN_STAGES = ("filled", "released")
MAX_DISMISSED = 1000


@dataclass(frozen=True)
class Exposure:
    item_id: str
    kind: str  # "login" or "secret"
    at: int
    agent: str  # "" when the run log no longer has the row


def _int(value: Any) -> int:
    return value if type(value) is int and value >= 0 else 0


def releases(events: Iterable[Mapping[str, Any]]) -> dict[str, tuple[str, int]]:
    """The newest release per item id: {id: (kind, unix time)}. Events without an item id are ignored."""
    out: dict[str, tuple[str, int]] = {}
    for event in events:
        if not isinstance(event, Mapping) or event.get("result") != "ok":
            continue
        kind = {LOGIN_EVENT: "login", SECRET_EVENT: "secret"}.get(str(event.get("event_type")))
        item_id = event.get("item_id")
        if kind is None or not isinstance(item_id, str) or not item_id:
            continue
        at = _int(event.get("timestamp"))
        if item_id not in out or at >= out[item_id][1]:
            out[item_id] = (kind, at)
    return out


def agent_name(runs: Iterable[Mapping[str, Any]], item_id: str, at: int) -> str:
    """The agent of the run-log row for this item nearest to ``at`` (within ``NAME_WINDOW``), else ""."""
    best: tuple[int, str] | None = None
    for row in runs:
        if not isinstance(row, Mapping) or row.get("stage") not in RUN_STAGES:
            continue
        items = row.get("items") if isinstance(row.get("items"), list) else []
        if not any(isinstance(i, Mapping) and i.get("item_id") == item_id for i in items):
            continue
        gap = abs(_int(row.get("at")) - at)
        name = str(row.get("agent") or "")
        if gap <= NAME_WINDOW and name and (best is None or gap < best[0]):
            best = (gap, name)
    return best[1] if best else ""


def login_changed_at(entry: Mapping[str, Any]) -> int:
    """When the login's password was last replaced (newest ``password_history`` row), 0 when never."""
    history = entry.get("password_history")
    rows = history if isinstance(history, list) else []
    return max((_int(row.get("changed_at")) for row in rows if isinstance(row, Mapping)), default=0)


def dismissed_map(values: Iterable[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values or ():
        if not isinstance(value, str) or "@" not in value:
            continue
        item_id, _, at = value.rpartition("@")
        if item_id and at.isdigit():
            out[item_id] = max(out.get(item_id, 0), int(at))
    return out


def dismiss(values: Iterable[Any], item_id: str, now: int) -> list[str]:
    """The dismissal list with ``item_id`` dismissed at ``now`` (one entry per item, newest last, bounded)."""
    kept = [v for v in (values or ()) if isinstance(v, str) and v.rpartition("@")[0] != item_id]
    return (kept + [f"{item_id}@{int(now)}"])[-MAX_DISMISSED:]


def exposures(events: Iterable[Mapping[str, Any]], runs: Iterable[Mapping[str, Any]],
              logins: Mapping[str, int], secrets: Mapping[str, int],
              dismissed: Iterable[Any] = ()) -> dict[str, Exposure]:
    """Current exposures by item id.

    ``logins`` maps each login id to its last password change (``login_changed_at``); ``secrets`` maps each
    secret item id to its ``updated_at``. Items missing there (deleted, or of another kind) never count.
    """
    runs = list(runs)
    hidden = dismissed_map(dismissed)
    out: dict[str, Exposure] = {}
    for item_id, (kind, at) in releases(events).items():
        changes = logins if kind == "login" else secrets
        if item_id not in changes or changes[item_id] > at or hidden.get(item_id, -1) >= at:
            continue
        out[item_id] = Exposure(item_id, kind, at, agent_name(runs, item_id, at))
    return out
