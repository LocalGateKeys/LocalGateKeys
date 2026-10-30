"""The sync pill and the Sync status sheet (UX plan workstream 6), from what the sync screen already knows.

The pill reads "Synced 2 min ago · 3 devices" with a dot: green (synced in the last day), orange (older
than a day, never synced yet, or a warning) or red (an error, or a card stopped). Off when no sync is set up.

Per-device times: a folder member's time is when its device file was last written (the header time in
the folder). A per-peer "last accepted that device's changes" time (``lastSyncedAt[deviceID]``) belongs
in ``sync/state.py``; when the status object carries ``peer_synced_at`` it is used instead.
"""
from __future__ import annotations

import time as _time
from typing import Any, Mapping
from ..i18n import t

DAY = 86400
STALE_PEER = 30 * DAY
_ROUTES = {"wifi": "Wi-Fi", "folder": "sync.cloudFolder"}


def _ago(seconds: int) -> str:
    if seconds < 60:
        return t("overview.age.justNow")
    if seconds < 3600:
        return t("syncStatus.minAgo", v1=seconds // 60)
    if seconds < DAY:
        return t("syncStatus.hAgo", v1=seconds // 3600)
    return t("syncStatus.dAgo", v1=seconds // DAY)


def _last_text(ts: int | None, now: float) -> str:
    if not ts:
        return "Never"
    clock = _time.strftime("%H:%M", _time.localtime(ts)) if now - ts < DAY else \
        _time.strftime("%d %b %H:%M", _time.localtime(ts))
    return t("syncStatus.lastSynced", clock=clock, v2=_ago(max(0, int(now) - int(ts))))


def _transport_times(status: Any) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for transport in getattr(status, "transports", ()) or ():
        name = getattr(transport, "name", None)
        if name in _ROUTES:
            value = getattr(transport, "last_sync", None)
            out[name] = int(value) if isinstance(value, (int, float)) and value > 0 else None
    return out


def _member_times(snapshot: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for member in getattr(snapshot, "members", ()) or ():
        written = getattr(member, "file_written_at", None)
        if isinstance(written, int) and written > 0:
            out[str(member.device_id)] = written
    return out


def summarize(view: Mapping[str, Any], status: Any = None, snapshot: Any = None, *,
              now: float | None = None) -> dict[str, Any]:
    """``view`` is ``SyncWebService.view()``; ``status`` and ``snapshot`` add the raw times."""
    now = _time.time() if now is None else now
    cards = [c for c in view.get("cards", []) if isinstance(c, Mapping)]
    active = [c for c in cards if c.get("state") not in ("off", "unavailable")]
    if not active:
        return {"state": "off", "colour": "grey", "text": t("syncStatus.syncIsOff"), "devices": [], "device_count": 0,
                "this_device": None, "last_synced_at": None, "pro": bool(view.get("pro", True))}
    times = _transport_times(status)
    member_times = _member_times(snapshot)
    peer_times = getattr(status, "peer_synced_at", None)
    peer_times = dict(peer_times) if isinstance(peer_times, Mapping) else {}
    devices: dict[str, dict[str, Any]] = {}
    this_device = None
    warnings: list[str] = []
    for card in active:
        route = str(card.get("key"))
        for member in card.get("members", []):
            if not isinstance(member, Mapping):
                continue
            if member.get("is_self"):
                this_device = this_device or {"name": str(member.get("name") or t("syncPage.thisPc"))}
                continue
            device_id = str(member.get("id"))
            entry = devices.setdefault(device_id, {"id": device_id, "name": str(member.get("name") or device_id),
                                                   "routes": [], "warnings": [], "last_synced_at": None})
            entry["routes"].append(route)
            if member.get("detail"):
                entry["warnings"].append(str(member["detail"]))
            ts = peer_times.get(device_id) or (member_times.get(device_id) if route == "folder" else None)
            if isinstance(ts, (int, float)) and ts > 0 and (entry["last_synced_at"] or 0) < ts:
                entry["last_synced_at"] = int(ts)
    rows = []
    for entry in devices.values():
        ts = entry["last_synced_at"]
        if ts and now - ts > STALE_PEER:
            entry["warnings"].append(t("syncStatus.notSeenIn30Days"))
        rows.append({**entry, "route": t("common.listAnd").join(t(_ROUTES[r]) for r in ("wifi", "folder") if r in entry["routes"]),
                     "last_text": _last_text(ts, now)})
    rows.sort(key=lambda r: r["name"].casefold())
    for row in rows:
        warnings.extend(row["warnings"])
    last = max((t for t in times.values() if t), default=None)
    severities = {(c.get("banner") or {}).get("severity") for c in active} | \
        {(i or {}).get("severity") for c in active for i in c.get("issues", [])}
    if any(c.get("state") in ("stopped", "broken") for c in active) or "error" in severities:
        colour, state = "red", "error"
    elif last is None or now - last > DAY or "warning" in severities or warnings:
        colour, state = "orange", "warning"
    else:
        colour, state = "green", "ok"
    count = len(rows) + 1  # this device too
    head = t("status.sync.attention") if state == "error" else (t("syncStatus.synced", ago=_ago(max(0, int(now) - last)))
                                                            if last else t("status.sync.never"))
    return {"state": state, "colour": colour, "text": f"{head} · {t('syncStatus.deviceCount', count=count)}", "devices": rows,
            "device_count": count, "this_device": {**(this_device or {"name": t("syncPage.thisPc")}),
                                                   "last_text": _last_text(last, now)},
            "last_synced_at": last, "pro": bool(view.get("pro", True))}
