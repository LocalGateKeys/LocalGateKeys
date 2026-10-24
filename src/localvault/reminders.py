"""Encrypted, content-free reminders for live typed catalog items.

Reminders deliberately contain no title or free-form message.  They point at
an authenticated typed item and carry only bounded scheduling metadata.  The
optional scheduler is an app-running, in-memory poller; it never opens a
network connection or caches item payloads.
"""
from __future__ import annotations

import calendar as _calendar
import copy
import datetime as _datetime
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

from .item_schema import MAX_REMINDERS, ItemSchemaError, validate_reminders
from .vault import VaultError, VaultLockedError

MAX_SCHEDULES = 20_000
MAX_OCCURRENCIES_PER_SCHEDULE = 100
MAX_OCCURRENCIES_PROFILE = 5_000
MAX_INTERVAL = 365
MAX_END_COUNT = 10_000
MAX_DEADLINE_DAYS = 3_650
_UNITS = {"day", "week", "month", "year"}
_EVENT_KINDS = {"renewal", "deadline"}


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ItemSchemaError(f"{field} must be a UUID")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ItemSchemaError(f"{field} must be a UUID") from None


def _date(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value in (None, ""):
        return ""
    if isinstance(value, _datetime.datetime):
        raise ItemSchemaError(f"{field} must be an ISO date (YYYY-MM-DD)")
    if isinstance(value, _datetime.date):
        value = value.isoformat()
    if not isinstance(value, str) or len(value) != 10:
        raise ItemSchemaError(f"{field} must be an ISO date (YYYY-MM-DD)")
    try:
        _datetime.date.fromisoformat(value)
    except ValueError:
        raise ItemSchemaError(f"{field} must be an ISO date (YYYY-MM-DD)") from None
    return value


def _today(value: Any = None) -> _datetime.date:
    if value is None:
        return _datetime.date.today()
    return _datetime.date.fromisoformat(_date(value, "reference date"))


def _bounded_int(value: Any, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ItemSchemaError(f"{field} must be between {low} and {high}")
    return value


def _date_or_empty(value: Any, field: str) -> str:
    return _date(value, field, allow_empty=True)


def _schedule_id(value: Any = None) -> str:
    return _uuid(value, "schedule id") if value is not None else str(uuid.uuid4())


def _month_date(year: int, month: int, day: int) -> _datetime.date:
    return _datetime.date(year, month, min(day, _calendar.monthrange(year, month)[1]))


def _occurrence_date(anchor: _datetime.date, unit: str, interval: int, number: int) -> _datetime.date:
    """Compute from the original anchor, retaining month-end/leap semantics."""

    if number < 0:
        raise ItemSchemaError("occurrence number must not be negative")
    steps = interval * number
    if unit == "day":
        return anchor + _datetime.timedelta(days=steps)
    if unit == "week":
        return anchor + _datetime.timedelta(weeks=steps)
    if unit == "month":
        offset = anchor.month - 1 + steps
        return _month_date(anchor.year + offset // 12, offset % 12 + 1, anchor.day)
    if unit == "year":
        return _month_date(anchor.year + steps, anchor.month, anchor.day)
    raise ItemSchemaError("unsupported recurrence unit")


def _occurrence_number(anchor: _datetime.date, unit: str, interval: int, target: _datetime.date) -> int:
    """Return the greatest occurrence at or before target without scanning."""

    if target < anchor:
        return -1
    if unit == "day":
        return (target - anchor).days // interval
    if unit == "week":
        return (target - anchor).days // (interval * 7)
    if unit == "month":
        months = (target.year - anchor.year) * 12 + target.month - anchor.month
        number = max(0, months // interval)
        # Month-end clamping means the direct estimate can land after target.
        while number >= 0 and _occurrence_date(anchor, unit, interval, number) > target:
            number -= 1
        while _occurrence_date(anchor, unit, interval, number + 1) <= target:
            number += 1
        return number
    if unit == "year":
        number = max(0, (target.year - anchor.year) // interval)
        while number >= 0 and _occurrence_date(anchor, unit, interval, number) > target:
            number -= 1
        while _occurrence_date(anchor, unit, interval, number + 1) <= target:
            number += 1
        return number
    raise ItemSchemaError("unsupported recurrence unit")


class ReminderScheduler:
    """A local poller with only safe reminder metadata in its callback.

    The scheduler has no notification implementation.  A caller may provide
    a callback to ``start``; callback rows contain only IDs and dates and must
    still be acted on explicitly by the caller.  ``VaultSession.lock`` calls
    ``stop`` and drops this object, so it cannot outlive the unlocked profile.
    """

    def __init__(self, service: ReminderService, *, interval_seconds: int = 60) -> None:
        self.service = service
        self.interval_seconds = max(1, min(int(interval_seconds), 3600))
        self._active = False
        self._stop_event: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._callback: Callable[[list[dict[str, str]]], None] | None = None
        self._session_generation: str | None = None

    @property
    def active(self) -> bool:
        return self._active

    @property
    def running(self) -> bool:
        return self.active

    def start(self, callback: Callable[[list[dict[str, str]]], None] | None = None) -> None:
        if not getattr(self.service.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        if callback is not None and not callable(callback):
            raise TypeError("scheduler callback must be callable")
        if self._active:
            if callback is not None:
                self._callback = callback
            return
        self._callback = callback
        self._session_generation = getattr(self.service.session, "workspace_session_generation", None)
        self._stop_event = threading.Event()
        self._active = True
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="localgatekeys-reminders")
        self._thread.start()

    def _run(self) -> None:
        event = self._stop_event
        while self._active and event is not None and not event.wait(self.interval_seconds):
            try:
                rows = self.poll()
                callback = self._callback
                if callback is not None and rows:
                    callback(rows)
            except (VaultError, ItemSchemaError):
                # A lock/profile switch is a normal stop condition.  The
                # scheduler must never surface decrypted payloads as errors.
                self.stop()
                return
            except Exception:
                # A caller callback is not allowed to take down the app's
                # lifecycle thread or turn a reminder into a secret log.
                continue

    def poll(self, on: Any = None) -> list[dict[str, str]]:
        if not self._active or not getattr(self.service.session, "is_unlocked", False):
            return []
        generation = getattr(self.service.session, "workspace_session_generation", None)
        if self._session_generation is not None and generation != self._session_generation:
            self.stop()
            return []
        rows = self.service.due(on)
        recurring = self.service.process(on)
        # Only safe catalog references are returned.  No title, URL, note,
        # license value, attachment name, or other item payload crosses this
        # boundary.
        safe = [
            {"id": str(row["id"]), "item_id": str(row["item_id"]),
             "due_date": str(row["due_date"])}
            for row in rows
        ]
        # Recurring callbacks carry only schedule identifiers and dates. They
        # deliberately omit the item title and all obligation payload.
        safe.extend(
            {"id": str(row["id"]), "item_id": str(row["id"]), "due_date": str(row["due_date"])}
            for row in recurring
        )
        return safe

    def stop(self) -> None:
        self._active = False
        event, thread = self._stop_event, self._thread
        self._stop_event = None
        self._thread = None
        self._callback = None
        self._session_generation = None
        if event is not None:
            event.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    close = stop


class ReminderService:
    """CRUD and date queries for encrypted reminder catalog records."""

    def __init__(self, session: Any) -> None:
        self.session = session

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _live_items(self, payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        items = payload.get("items", [])
        if not isinstance(items, list):
            raise VaultError("Typed catalog items are malformed")
        return {
            str(item["id"]): item
            for item in items
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }

    def _reference(self, item_id: str, payload: dict[str, Any]) -> str:
        item_id = _uuid(item_id, "reminder item id")
        if item_id not in self._live_items(payload):
            raise ItemSchemaError("Reminder must reference a live typed item")
        return item_id

    def _records(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        raw_records = payload.get("reminders", [])
        records = validate_reminders(raw_records)
        live_ids = set(self._live_items(payload))
        # Canonicalize rows in the session payload so mutation methods update
        # the encrypted catalog rather than a detached validator result. A
        # stale row may have come from an older build or a delete performed
        # before reminder support; prune it before it can be returned, counted,
        # or reused.
        canonical: list[dict[str, Any]] = []
        raw_rows = raw_records if isinstance(raw_records, list) else []
        for raw_row, row in zip(raw_rows, records):
            if row["item_id"] not in live_ids:
                continue
            if isinstance(raw_row, dict):
                raw_row.clear()
                raw_row.update(row)
                canonical.append(raw_row)
            else:
                canonical.append(row)
        payload["reminders"] = canonical
        return canonical

    def _find(self, reminder_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        reminder_id = _uuid(reminder_id, "reminder id")
        return next((row for row in self._records(payload) if row["id"] == reminder_id), None)

    def _mutate(self, event_type: str, item_id: str | None, callback: Callable[[], Any]) -> Any:
        with self.session.transaction():
            result = callback()
            self.session.activity.record(event_type, item_id=item_id, persist=False)
            return result

    @property
    def scheduler(self) -> ReminderScheduler:
        return self.session.reminder_scheduler

    def list(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._records(self._payload()))

    list_reminders = list

    def get(self, reminder_id: str) -> dict[str, Any] | None:
        return copy.deepcopy(self._find(reminder_id, self._payload()))

    @property
    def default_lead_days(self) -> int:
        payload = self._payload()
        preferences = payload.get("preferences", {})
        value = preferences.get("reminder_default_lead_days", 0) if isinstance(preferences, dict) else 0
        return value if type(value) is int and 0 <= value <= 3650 else 0

    def set_default_lead_days(self, days: int) -> int:
        if type(days) is not int or not 0 <= days <= 3650:
            raise ItemSchemaError("reminder default lead_days is malformed")
        payload = self._payload()
        preferences = payload.setdefault("preferences", {})
        if not isinstance(preferences, dict):
            raise VaultError("Vault preferences are malformed")

        def change() -> int:
            preferences["reminder_default_lead_days"] = days
            payload["updated_at"] = int(time.time())
            return days

        return self._mutate("reminder.update", None, change)

    def create(self, item_id: str, due_date: Any, *, lead_days: int | None = None,
               reminder_id: str | None = None) -> str:
        payload = self._payload()
        item_id = self._reference(item_id, payload)
        due_date = _date(due_date, "reminder due date")
        if lead_days is None:
            lead_days = self.default_lead_days
        if type(lead_days) is not int or not 0 <= lead_days <= 3650:
            raise ItemSchemaError("reminder lead_days is malformed")
        reminder_id = _uuid(reminder_id, "reminder id") if reminder_id is not None else str(uuid.uuid4())

        def add() -> str:
            records = self._records(payload)
            if len(records) >= MAX_REMINDERS:
                raise ItemSchemaError("The reminder limit has been reached")
            if any(isinstance(row, dict) and row.get("id") == reminder_id for row in records):
                raise ItemSchemaError("A reminder with this ID already exists")
            records.append({"id": reminder_id, "item_id": item_id, "due_date": due_date,
                            "lead_days": lead_days, "status": "pending",
                            "snooze_until": "", "last_notified": ""})
            payload["updated_at"] = int(time.time())
            return reminder_id

        return self._mutate("reminder.create", item_id, add)

    create_reminder = create

    def update(self, reminder_id: str, *, item_id: str | None = None,
               due_date: Any = None, lead_days: int | None = None) -> bool:
        payload = self._payload()
        record = self._find(reminder_id, payload)
        if record is None:
            return False
        new_item_id = self._reference(item_id, payload) if item_id is not None else record["item_id"]
        new_due_date = _date(due_date, "reminder due date") if due_date is not None else record["due_date"]
        if lead_days is not None and (type(lead_days) is not int or not 0 <= lead_days <= 3650):
            raise ItemSchemaError("reminder lead_days is malformed")

        def change() -> bool:
            record["item_id"] = new_item_id
            record["due_date"] = new_due_date
            if lead_days is not None:
                record["lead_days"] = lead_days
            payload["updated_at"] = int(time.time())
            return True

        return self._mutate("reminder.update", new_item_id, change)

    update_reminder = update

    def reschedule(self, reminder_id: str, due_date: Any, *, lead_days: int | None = None) -> bool:
        """Explicit editor spelling for changing a reminder's schedule."""
        return self.update(reminder_id, due_date=due_date, lead_days=lead_days)

    reschedule_reminder = reschedule

    def delete(self, reminder_id: str) -> bool:
        payload = self._payload()
        record = self._find(reminder_id, payload)
        if record is None:
            return False
        item_id = record["item_id"]

        def remove() -> bool:
            records = payload.setdefault("reminders", [])
            records[:] = [row for row in records if row.get("id") != record["id"]]
            payload["updated_at"] = int(time.time())
            return True

        return self._mutate("reminder.delete", item_id, remove)

    delete_reminder = delete

    def complete(self, reminder_id: str) -> bool:
        payload = self._payload()
        record = self._find(reminder_id, payload)
        if record is None:
            return False
        item_id = record["item_id"]

        def finish() -> bool:
            record["status"] = "dismissed"
            record["snooze_until"] = ""
            payload["updated_at"] = int(time.time())
            return True

        return self._mutate("reminder.complete", item_id, finish)

    complete_reminder = complete
    # Dismissal is intentionally the same content-free state transition as
    # completion; no title or message is introduced into the catalog.
    dismiss = complete
    dismiss_reminder = complete

    def snooze(self, reminder_id: str, until: Any = None, *, days: int | None = None,
               from_date: Any = None) -> bool:
        payload = self._payload()
        record = self._find(reminder_id, payload)
        if record is None:
            return False
        if until is None:
            if type(days) is not int or not 0 <= days <= 3650:
                raise ItemSchemaError("snooze days must be between 0 and 3650")
            until = _today(from_date) + _datetime.timedelta(days=days)
        snooze_until = _date(until, "reminder snooze_until")
        item_id = record["item_id"]

        def defer() -> bool:
            record["status"] = "snoozed"
            record["snooze_until"] = snooze_until
            payload["updated_at"] = int(time.time())
            return True

        return self._mutate("reminder.snooze", item_id, defer)

    snooze_reminder = snooze

    def unsnooze(self, reminder_id: str) -> bool:
        payload = self._payload()
        record = self._find(reminder_id, payload)
        if record is None:
            return False
        item_id = record["item_id"]

        def resume() -> bool:
            record["status"] = "pending"
            record["snooze_until"] = ""
            payload["updated_at"] = int(time.time())
            return True

        return self._mutate("reminder.update", item_id, resume)

    def _effective_date(self, record: dict[str, Any]) -> _datetime.date:
        due = _datetime.date.fromisoformat(record["due_date"])
        due -= _datetime.timedelta(days=record.get("lead_days", 0))
        snoozed = record.get("snooze_until", "")
        if record.get("status") == "snoozed" and snoozed:
            due = max(due, _datetime.date.fromisoformat(snoozed))
        return due

    def due(self, on: Any = None) -> list[dict[str, Any]]:
        target = _today(on)
        records = [row for row in self._records(self._payload())
                   if row.get("status") != "dismissed" and self._effective_date(row) == target]
        return copy.deepcopy(records)

    due_reminders = due

    def overdue(self, on: Any = None) -> list[dict[str, Any]]:
        target = _today(on)
        records = [row for row in self._records(self._payload())
                   if row.get("status") != "dismissed" and self._effective_date(row) < target]
        return copy.deepcopy(records)

    overdue_reminders = overdue

    def upcoming(self, days: int = 7, *, from_date: Any = None) -> list[dict[str, Any]]:
        if type(days) is not int or not 0 <= days <= 3650:
            raise ItemSchemaError("upcoming days must be between 0 and 3650")
        start = _today(from_date)
        end = start + _datetime.timedelta(days=days)
        records = [row for row in self._records(self._payload())
                   if row.get("status") != "dismissed"
                   and start <= self._effective_date(row) <= end]
        return copy.deepcopy(records)

    upcoming_reminders = upcoming

    # ------------------------------------------------------------------
    # Date-only recurring obligations (N08)
    # ------------------------------------------------------------------
    def _schedules(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        raw = payload.setdefault("reminder_schedules", [])
        if not isinstance(raw, list) or len(raw) > MAX_SCHEDULES:
            raise ItemSchemaError("reminder schedules are malformed or exceed the limit")
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        live_ids = set(self._live_items(payload))
        for row in raw:
            if not isinstance(row, dict):
                raise ItemSchemaError("reminder schedule must be an object")
            try:
                sid = _schedule_id(row.get("id"))
                item_id = _uuid(row.get("item_id"), "schedule item id")
                anchor = _date(row.get("anchor"), "schedule anchor")
                unit = str(row.get("unit", "day")).casefold()
                interval = _bounded_int(row.get("interval", 1), "schedule interval", 1, MAX_INTERVAL)
                end_date = _date_or_empty(row.get("end_date", ""), "schedule end date")
                max_count = row.get("max_count")
                if max_count is not None:
                    max_count = _bounded_int(max_count, "schedule maximum count", 1, MAX_END_COUNT)
                deadline_date = _date_or_empty(row.get("deadline_date", ""), "cancellation deadline")
                deadline_days = row.get("deadline_days_before")
                if deadline_days is not None:
                    deadline_days = _bounded_int(deadline_days, "cancellation deadline days", 0, MAX_DEADLINE_DAYS)
                version = _bounded_int(row.get("version", 1), "schedule version", 1, 2**63 - 1)
                if unit not in _UNITS:
                    raise ItemSchemaError("schedule recurrence unit is malformed")
                if end_date and end_date < anchor:
                    raise ItemSchemaError("schedule end date cannot precede its anchor")
                if deadline_date and deadline_days is not None:
                    raise ItemSchemaError("schedule cancellation deadline is ambiguous")
                if sid in seen:
                    raise ItemSchemaError("duplicate reminder schedule IDs")
                seen.add(sid)
                if item_id not in live_ids:
                    continue
                if type(row.get("paused", False)) is not bool or type(row.get("cancelled", False)) is not bool:
                    raise ItemSchemaError("schedule state is malformed")
                result.append({
                    "id": sid, "item_id": item_id, "anchor": anchor, "unit": unit,
                    "interval": interval, "end_date": end_date, "max_count": max_count,
                    "deadline_date": deadline_date, "deadline_days_before": deadline_days,
                    "version": version, "paused": bool(row.get("paused", False)),
                    "cancelled": bool(row.get("cancelled", False)),
                    "snooze_until": _date_or_empty(row.get("snooze_until", ""), "schedule snooze_until"),
                })
            except (TypeError, ValueError) as exc:
                raise ItemSchemaError("reminder schedule is malformed") from exc
        # Keep the authenticated payload canonical without adding any secrets.
        payload["reminder_schedules"] = result
        return result

    def _ledger(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        raw = payload.setdefault("reminder_occurrences", [])
        if not isinstance(raw, list):
            raise ItemSchemaError("reminder occurrence ledger is malformed")
        if len(raw) > MAX_OCCURRENCIES_PROFILE:
            # Keep the newest bounded records. Watermarks remain separate, so
            # pruning never permits a duplicate notification or completion.
            del raw[:-MAX_OCCURRENCIES_PROFILE]
        return raw

    def _watermarks(self, payload: dict[str, Any]) -> dict[str, Any]:
        value = payload.setdefault("reminder_watermarks", {})
        if not isinstance(value, dict):
            raise ItemSchemaError("reminder notification watermarks are malformed")
        return value

    def list_schedules(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._schedules(self._payload()))

    schedules = list_schedules

    def get_schedule(self, schedule_id: str) -> dict[str, Any] | None:
        sid = _uuid(schedule_id, "schedule id")
        return copy.deepcopy(next((row for row in self._schedules(self._payload()) if row["id"] == sid), None))

    def create_schedule(
        self,
        item_id: str,
        anchor: Any,
        *,
        unit: str = "day",
        interval: int = 1,
        end_date: Any = None,
        max_count: int | None = None,
        deadline_date: Any = None,
        deadline_days_before: int | None = None,
        schedule_id: str | None = None,
        paused: bool = False,
        recurrence: str | None = None,
        until: Any = None,
        count: int | None = None,
    ) -> str:
        payload = self._payload()
        item_id = self._reference(item_id, payload)
        anchor_date = _today(anchor)
        if recurrence is not None:
            unit = recurrence
        if until is not None:
            end_date = until
        if count is not None:
            max_count = count
        unit = str(unit).casefold()
        if unit not in _UNITS:
            raise ItemSchemaError("schedule recurrence unit is malformed")
        interval = _bounded_int(interval, "schedule interval", 1, MAX_INTERVAL)
        end_date = _date_or_empty(end_date, "schedule end date")
        if end_date and end_date < anchor_date.isoformat():
            raise ItemSchemaError("schedule end date cannot precede its anchor")
        if max_count is not None:
            max_count = _bounded_int(max_count, "schedule maximum count", 1, MAX_END_COUNT)
        deadline_date = _date_or_empty(deadline_date, "cancellation deadline")
        if deadline_days_before is not None:
            deadline_days_before = _bounded_int(deadline_days_before, "cancellation deadline days", 0, MAX_DEADLINE_DAYS)
        if deadline_date and deadline_days_before is not None:
            raise ItemSchemaError("schedule cancellation deadline is ambiguous")
        sid = _schedule_id(schedule_id)

        def add() -> str:
            schedules = self._schedules(payload)
            if len(schedules) >= MAX_SCHEDULES or any(row["id"] == sid for row in schedules):
                raise ItemSchemaError("A schedule with this ID already exists or the limit was reached")
            schedules.append({
                "id": sid, "item_id": item_id, "anchor": anchor_date.isoformat(), "unit": unit,
                "interval": interval, "end_date": end_date, "max_count": max_count,
                "deadline_date": deadline_date, "deadline_days_before": deadline_days_before,
                "version": 1, "paused": bool(paused), "cancelled": False, "snooze_until": "",
            })
            payload["updated_at"] = int(time.time())
            return sid

        return self._mutate("reminder.create", item_id, add)

    create_recurring = create_schedule
    schedule = create_schedule

    def update_schedule(self, schedule_id: str, **changes: Any) -> bool:
        payload = self._payload()
        sid = _uuid(schedule_id, "schedule id")
        schedule = next((row for row in self._schedules(payload) if row["id"] == sid), None)
        if schedule is None:
            return False
        allowed = {"anchor", "unit", "recurrence", "interval", "end_date", "until", "max_count", "count",
                   "deadline_date", "deadline_days_before", "paused"}
        if set(changes) - allowed:
            raise ItemSchemaError("unsupported schedule fields")
        # Build a validated replacement using the same direct rules as create.
        anchor = _today(changes.get("anchor", schedule["anchor"]))
        unit = str(changes.get("recurrence", changes.get("unit", schedule["unit"]))).casefold()
        interval = _bounded_int(changes.get("interval", schedule["interval"]), "schedule interval", 1, MAX_INTERVAL)
        end_date = _date_or_empty(changes.get("until", changes.get("end_date", schedule["end_date"])), "schedule end date")
        max_count = changes.get("count", changes.get("max_count", schedule["max_count"]))
        if max_count is not None:
            max_count = _bounded_int(max_count, "schedule maximum count", 1, MAX_END_COUNT)
        deadline_date = _date_or_empty(changes.get("deadline_date", schedule["deadline_date"]), "cancellation deadline")
        deadline_days = changes.get("deadline_days_before", schedule["deadline_days_before"])
        if deadline_days is not None:
            deadline_days = _bounded_int(deadline_days, "cancellation deadline days", 0, MAX_DEADLINE_DAYS)
        if unit not in _UNITS or (end_date and end_date < anchor.isoformat()):
            raise ItemSchemaError("schedule dates or recurrence are malformed")
        if deadline_date and deadline_days is not None:
            raise ItemSchemaError("schedule cancellation deadline is ambiguous")

        def change() -> bool:
            schedule.update({
                "anchor": anchor.isoformat(), "unit": unit, "interval": interval,
                "end_date": end_date, "max_count": max_count, "deadline_date": deadline_date,
                "deadline_days_before": deadline_days, "paused": bool(changes.get("paused", schedule["paused"])),
                "version": int(schedule["version"]) + 1, "snooze_until": "",
            })
            payload["updated_at"] = int(time.time())
            return True
        return self._mutate("reminder.update", schedule["item_id"], change)

    def pause_schedule(self, schedule_id: str) -> bool:
        return self.update_schedule(schedule_id, paused=True)

    pause = pause_schedule

    def resume_schedule(self, schedule_id: str) -> bool:
        return self.update_schedule(schedule_id, paused=False)

    resume = resume_schedule

    def mark_cancelled(self, schedule_id: str) -> bool:
        payload = self._payload()
        sid = _uuid(schedule_id, "schedule id")
        schedule = next((row for row in self._schedules(payload) if row["id"] == sid), None)
        if schedule is None:
            return False

        def cancel() -> bool:
            schedule["cancelled"] = True
            schedule["paused"] = True
            payload["updated_at"] = int(time.time())
            return True
        return self._mutate("reminder.update", schedule["item_id"], cancel)

    cancel_schedule = mark_cancelled
    cancel = mark_cancelled

    def _schedule_event_rows(self, schedule: dict[str, Any], target: _datetime.date) -> list[dict[str, Any]]:
        if schedule["paused"] or schedule["cancelled"] or target < _datetime.date.fromisoformat(schedule["anchor"]):
            return []
        anchor = _datetime.date.fromisoformat(schedule["anchor"])
        number = _occurrence_number(anchor, schedule["unit"], schedule["interval"], target)
        if schedule["max_count"] is not None:
            number = min(number, schedule["max_count"] - 1)
        if number < 0:
            return []
        if schedule["end_date"]:
            while number >= 0 and _occurrence_date(anchor, schedule["unit"], schedule["interval"], number) > _datetime.date.fromisoformat(schedule["end_date"]):
                number -= 1
        # A bounded direct calculation is used for normal ranges. Only the
        # bounded retention window is returned to callers.
        first = max(0, number - MAX_OCCURRENCIES_PER_SCHEDULE + 1)
        return [
            {"schedule_id": schedule["id"], "schedule_version": schedule["version"], "number": n,
             "due_date": _occurrence_date(anchor, schedule["unit"], schedule["interval"], n).isoformat()}
            for n in range(first, number + 1)
        ]

    def _deadline_date(self, schedule: dict[str, Any], occurrence: dict[str, Any]) -> str:
        # An explicit date is a reviewed, single-cycle deadline. Recurring
        # deadlines use days-before-renewal and are calculated per occurrence.
        if schedule["deadline_date"] and int(occurrence.get("number", 0)) == 0:
            return schedule["deadline_date"]
        days = schedule["deadline_days_before"]
        if days is None:
            return ""
        return (_datetime.date.fromisoformat(occurrence["due_date"]) - _datetime.timedelta(days=days)).isoformat()

    def process(self, on: Any = None) -> list[dict[str, str]]:
        """Materialize due occurrences and return generic one-shot events."""
        payload = self._payload()
        with self.session.transaction():
            return self._process_impl(on, payload)

    def _process_impl(self, on: Any, payload: dict[str, Any]) -> list[dict[str, str]]:
        target = _today(on)
        schedules = self._schedules(payload)
        ledger = self._ledger(payload)
        watermarks = self._watermarks(payload)
        events: list[dict[str, str]] = []
        changed = False
        for schedule in schedules:
            candidate_target = target
            # A cancellation deadline can precede the renewal date, so the
            # next future occurrence must be materialized while its deadline
            # is in the notification window.
            if schedule["deadline_days_before"] is not None:
                candidate_target = target + _datetime.timedelta(days=schedule["deadline_days_before"])
            elif schedule["deadline_date"] and target >= _datetime.date.fromisoformat(schedule["deadline_date"]):
                candidate_target = max(target, _datetime.date.fromisoformat(schedule["anchor"]))
            candidates = self._schedule_event_rows(schedule, candidate_target)
            latest_due = candidates[-1]["due_date"] if candidates else ""
            # The latest occurrence is due only when its date is on/before the
            # target. Earlier unresolved windows are coalesced as missed.
            for occurrence in candidates:
                due = occurrence["due_date"]
                key = f"{schedule['id']}:{schedule['version']}:{due}"
                row = next((item for item in ledger if item.get("key") == key), None)
                if row is None:
                    row = {
                        "key": key, "schedule_id": schedule["id"], "schedule_version": schedule["version"],
                        "due_date": due, "status": "pending", "deadline_status": "pending",
                        "renewal_notified": False, "deadline_notified": False,
                        "renewal_completed": False, "deadline_completed": False,
                        "renewal_snooze_until": "", "deadline_snooze_until": "", "missed_count": 0,
                    }
                    ledger.append(row)
                    changed = True
                # Old windows are one missed obligation; do not mark a due
                # event completed merely because the user was away.
                if _datetime.date.fromisoformat(due) < target and not row["renewal_completed"]:
                    if row["status"] == "pending":
                        row["status"] = "missed"
                        row["missed_count"] = int(row.get("missed_count", 0)) + 1
                        changed = True
                if due == latest_due and _datetime.date.fromisoformat(due) <= target and not row["renewal_notified"] and not row["renewal_completed"]:
                    snooze = row.get("renewal_snooze_until", "")
                    if not snooze or _datetime.date.fromisoformat(snooze) <= target:
                        row["renewal_notified"] = True
                        watermarks[key + ":renewal"] = True
                        events.append({"id": schedule["id"], "schedule_id": schedule["id"], "due_date": due, "kind": "renewal"})
                        changed = True
                deadline = self._deadline_date(schedule, occurrence)
                if deadline and not row["deadline_completed"] and _datetime.date.fromisoformat(deadline) <= target:
                    if _datetime.date.fromisoformat(deadline) < target and row["deadline_status"] == "pending":
                        row["deadline_status"] = "missed"
                        row["missed_count"] = int(row.get("missed_count", 0)) + 1
                        changed = True
                    snooze = row.get("deadline_snooze_until", "")
                    explicit_deadline = bool(schedule["deadline_date"] and int(occurrence.get("number", 0)) == 0)
                    if (explicit_deadline or due == latest_due) and not row["deadline_notified"] and (not snooze or _datetime.date.fromisoformat(snooze) <= target):
                        row["deadline_notified"] = True
                        row["deadline_status"] = "notified" if row["deadline_status"] == "pending" else row["deadline_status"]
                        watermarks[key + ":deadline"] = True
                        events.append({"id": schedule["id"], "schedule_id": schedule["id"], "due_date": due, "kind": "deadline"})
                        changed = True
        # Keep a bounded ledger while preserving independent watermarks.
        if len(ledger) > MAX_OCCURRENCIES_PROFILE:
            del ledger[:-MAX_OCCURRENCIES_PROFILE]
            changed = True
        if changed:
            payload["updated_at"] = int(time.time())
        return events

    advance = process
    poll_events = process

    def due_occurrences(self, on: Any = None) -> list[dict[str, Any]]:
        """Return date-only schedule metadata due on a date without notifying."""
        target = _today(on)
        rows: list[dict[str, Any]] = []
        for schedule in self._schedules(self._payload()):
            if schedule["paused"] or schedule["cancelled"]:
                continue
            candidates = self._schedule_event_rows(schedule, target)
            if candidates and candidates[-1]["due_date"] == target.isoformat():
                row = dict(candidates[-1])
                row["kind"] = "renewal"
                deadline = self._deadline_date(schedule, row)
                if deadline and deadline == target.isoformat():
                    row["kind"] = "deadline"
                rows.append(row)
        return rows

    due_schedules = due_occurrences
    recurring_due = due_occurrences

    def next_occurrence(self, schedule_id: str, *, after: Any = None) -> dict[str, Any] | None:
        schedule = self.get_schedule(schedule_id)
        if schedule is None or schedule["paused"] or schedule["cancelled"]:
            return None
        target = _today(after) if after is not None else _datetime.date.fromisoformat(schedule["anchor"]) - _datetime.timedelta(days=1)
        number = _occurrence_number(_datetime.date.fromisoformat(schedule["anchor"]), schedule["unit"], schedule["interval"], target) + 1
        if schedule["max_count"] is not None and number >= schedule["max_count"]:
            return None
        due = _occurrence_date(_datetime.date.fromisoformat(schedule["anchor"]), schedule["unit"], schedule["interval"], number)
        if schedule["end_date"] and due > _datetime.date.fromisoformat(schedule["end_date"]):
            return None
        result = {"schedule_id": schedule["id"], "schedule_version": schedule["version"], "number": number, "due_date": due.isoformat()}
        result["deadline_date"] = self._deadline_date(schedule, result)
        return result

    def occurrence_history(self, schedule_id: str | None = None) -> list[dict[str, Any]]:
        payload = self._payload()
        rows = self._ledger(payload)
        if schedule_id is not None:
            sid = _uuid(schedule_id, "schedule id")
            rows = [row for row in rows if row.get("schedule_id") == sid]
        return copy.deepcopy(rows)

    occurrences = occurrence_history
    ledger = occurrence_history

    def _find_occurrence(self, schedule_id: str, due_date: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
        sid = _uuid(schedule_id, "schedule id")
        due = _date(due_date, "occurrence due date")
        return next((row for row in self._ledger(payload) if row.get("schedule_id") == sid and row.get("due_date") == due), None)

    def complete_occurrence(self, schedule_id: str, due_date: Any, *, event_kind: str = "renewal") -> bool:
        if event_kind not in _EVENT_KINDS:
            raise ItemSchemaError("event kind is malformed")
        payload = self._payload()
        row = self._find_occurrence(schedule_id, due_date, payload)
        if row is None:
            return False
        schedule = next((item for item in self._schedules(payload) if item["id"] == row["schedule_id"]), None)
        item_id = schedule["item_id"] if schedule else None

        def complete() -> bool:
            row[f"{event_kind}_completed"] = True
            if event_kind == "renewal":
                row["status"] = "completed"
            else:
                row["deadline_status"] = "completed"
            payload["reminder_watermarks"][row["key"] + ":" + event_kind + ":completed"] = True
            payload["updated_at"] = int(time.time())
            return True
        return self._mutate("reminder.complete", item_id, complete)

    complete_schedule_occurrence = complete_occurrence

    def snooze_occurrence(self, schedule_id: str, due_date: Any, until: Any = None, *, days: int | None = None,
                          event_kind: str = "renewal", from_date: Any = None) -> bool:
        if event_kind not in _EVENT_KINDS:
            raise ItemSchemaError("event kind is malformed")
        payload = self._payload()
        row = self._find_occurrence(schedule_id, due_date, payload)
        if row is None:
            return False
        if until is None:
            days = _bounded_int(days, "snooze days", 0, 3650)
            until = _today(from_date) + _datetime.timedelta(days=days)
        value = _date(until, "occurrence snooze_until")
        schedule = next((item for item in self._schedules(payload) if item["id"] == row["schedule_id"]), None)

        def defer() -> bool:
            row[f"{event_kind}_snooze_until"] = value
            payload["updated_at"] = int(time.time())
            return True
        return self._mutate("reminder.snooze", schedule["item_id"] if schedule else None, defer)

    snooze_event = snooze_occurrence

    def complete_deadline(self, schedule_id: str, due_date: Any) -> bool:
        return self.complete_occurrence(schedule_id, due_date, event_kind="deadline")

    acknowledge_deadline = complete_deadline

    def clear_schedule(self) -> None:
        self.scheduler.stop()
