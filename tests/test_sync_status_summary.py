"""UX plan workstream 6: the sync pill colours and the Sync status sheet rows."""
from __future__ import annotations

from types import SimpleNamespace

from localvault.app.sync_status import summarize

NOW = 1_800_000_000


def _view(wifi="off", folder="on", members=(), banner=None, issues=()):
    return {"pro": True, "cards": [
        {"key": "wifi", "state": wifi, "members": [], "banner": None, "issues": []},
        {"key": "folder", "state": folder, "members": list(members), "banner": banner, "issues": list(issues)},
    ]}


ME = {"id": "me", "name": "Desk PC", "detail": "This PC", "is_self": True}
PHONE = {"id": "ph", "name": "Alex's iPhone", "detail": "", "is_self": False}


def _status(last):
    return SimpleNamespace(transports=[SimpleNamespace(name="folder", last_sync=last, issues=())])


def _snap(written=None):
    return SimpleNamespace(members=[SimpleNamespace(device_id="ph", file_written_at=written)])


def test_off_when_nothing_is_set_up():
    assert summarize(_view(folder="off"), now=NOW)["colour"] == "grey"


def test_green_with_device_count_and_route():
    out = summarize(_view(members=[ME, PHONE]), _status(NOW - 120), _snap(NOW - 840), now=NOW)
    assert out["colour"] == "green" and out["text"] == "Synced 2 min ago · 2 devices"
    row = out["devices"][0]
    assert row["name"] == "Alex's iPhone" and row["route"] == "Cloud folder"
    assert row["last_text"].endswith("(14 min ago)") and out["this_device"]["name"] == "Desk PC"


def test_orange_when_older_than_a_day_or_never_or_a_peer_is_stale():
    assert summarize(_view(members=[ME, PHONE]), _status(NOW - 2 * 86400), now=NOW)["colour"] == "orange"
    assert summarize(_view(members=[ME]), _status(None), now=NOW)["text"].startswith("Not synced yet")
    stale = summarize(_view(members=[ME, PHONE]), _status(NOW - 60), _snap(NOW - 40 * 86400), now=NOW)
    assert stale["colour"] == "orange" and "Not seen in 30 days" in stale["devices"][0]["warnings"]
    assert summarize(_view(members=[ME, PHONE]), _status(None), now=NOW)["devices"][0]["last_text"] == "Never"


def test_red_on_error_or_stopped():
    error = {"kind": "x", "severity": "error", "text": "Broken"}
    assert summarize(_view(members=[ME], banner=error), _status(NOW), now=NOW)["colour"] == "red"
    assert summarize(_view(folder="stopped", members=[ME]), _status(NOW), now=NOW)["state"] == "error"


def test_peer_time_from_sync_state_wins_and_both_routes_merge():
    view = _view(wifi="on", members=[ME, PHONE])
    view["cards"][0]["members"] = [dict(PHONE)]
    status = SimpleNamespace(transports=[SimpleNamespace(name="folder", last_sync=NOW, issues=())],
                             peer_synced_at={"ph": NOW - 60})
    row = summarize(view, status, _snap(NOW - 9000), now=NOW)["devices"][0]
    assert row["route"] == "Wi-Fi and Cloud folder" and row["last_synced_at"] == NOW - 60
