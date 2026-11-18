from __future__ import annotations

import json
import time

import pytest

from localvault.activity import ActivityService, event_hash
from localvault.vault import create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "activity chain test master password"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    return create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)


def _record(service: ActivityService, n: int, start: int | None = None) -> list[str]:
    now = int(time.time()) if start is None else start
    return [service.record("item.fill", timestamp=now + i, persist=False) for i in range(n)]


def test_chain_verifies_after_ten_events(session) -> None:
    service = ActivityService(session)
    _record(service, 10)
    report = service.verify_chain()
    assert report.ok and report.first_bad_id is None
    events = session._require_typed_catalog()["events"]
    assert all(len(e["prev_hash"]) == 64 for e in events)
    for prev, cur in zip(events, events[1:]):
        assert cur["prev_hash"] == event_hash(prev)


def test_tampered_event_is_reported(session) -> None:
    service = ActivityService(session)
    ids = _record(service, 10)
    events = session._require_typed_catalog()["events"]
    events[4]["result"] = "denied"
    report = service.verify_chain()
    assert not report.ok
    assert report.first_bad_id == ids[4]


def test_tampered_last_event_is_caught_by_head(session) -> None:
    service = ActivityService(session)
    ids = _record(service, 3)
    session._require_typed_catalog()["events"][-1]["count"] = 7
    report = service.verify_chain()
    assert not report.ok and report.first_bad_id == ids[-1]


def test_removed_event_is_reported(session) -> None:
    service = ActivityService(session)
    _record(service, 6)
    del session._require_typed_catalog()["events"][2]
    assert not service.verify_chain().ok


def test_truncation_emptying_and_stripping_are_reported(session) -> None:
    service = ActivityService(session)
    _record(service, 6)
    catalog = session._require_typed_catalog()
    kept = [dict(e) for e in catalog["events"]]
    del catalog["events"][-2:]
    assert not service.verify_chain().ok  # tail cut off
    catalog["events"] = kept[2:]
    assert not service.verify_chain().ok  # oldest events cut off without a checkpoint
    catalog["events"] = []
    assert not service.verify_chain().ok  # log emptied
    catalog["events"] = [{k: v for k, v in e.items() if k != "prev_hash"} for e in kept]
    assert not service.verify_chain().ok  # hashes stripped to pass as pre-chain events


def test_pruning_keeps_a_checkpoint_and_verifies(session) -> None:
    service = ActivityService(session, max_events=5_000)
    service.max_events = 5
    _record(service, 12)
    payload = session._require_typed_catalog()
    assert len(payload["events"]) == 5
    report = service.verify_chain()
    assert report.ok
    assert report.checkpoint == payload["events_chain"]["checkpoint"]
    assert payload["events"][0]["prev_hash"] == report.checkpoint


def test_chain_survives_save_and_reopen(session, tmp_path) -> None:
    service = ActivityService(session)
    _record(service, 4)
    session.save()
    reopened = unlock_vault(tmp_path / "vault.json", MASTER)
    assert ActivityService(reopened).verify_chain().ok


def test_legacy_events_without_hash_still_verify(session) -> None:
    payload = session._require_typed_catalog()
    payload["events"] = [{"id": "00000000-0000-4000-8000-000000000001", "event_type": "item.fill",
                          "timestamp": int(time.time()), "item_id": None, "result": "ok", "count": 0}]
    service = ActivityService(session)
    _record(service, 3)
    assert service.verify_chain().ok


def test_export_is_jsonl_with_hashes(session) -> None:
    service = ActivityService(session)
    _record(service, 3)
    text = service.export_jsonl()
    lines = text.strip().splitlines()
    assert len(lines) == 4  # header + 3 events
    header = json.loads(lines[0])
    assert header["type"] == "chain" and "checkpoint" in header and "head" in header
    rows = [json.loads(line) for line in lines[1:]]
    assert all("prev_hash" in row and "hash" in row for row in rows)
    assert rows[1]["prev_hash"] == rows[0]["hash"]


def test_security_model_row_reflects_chain_state() -> None:
    from localvault.shell.security_model import access_log_row

    ok_row = access_log_row(True)
    bad_row = access_log_row(False)
    assert ok_row.meta_tone == "neutral" and bad_row.meta_tone == "warning"
    assert ok_row.label != bad_row.label


def test_shared_vector() -> None:
    """Pinned for ActivityChainTests.swift and ActivityChainTest.kt (byte-exact canonical JSON)."""
    from localvault.activity import GENESIS_HASH

    first = {"id": "00000000-0000-4000-8000-000000000001", "event_type": "agent.request", "timestamp": 1762905600,
             "item_id": None, "result": "ok", "count": 0, "prev_hash": GENESIS_HASH}
    first_hash = "a41a74612fea40f020a620bfc5388089682665bc54d23e81c8b379376f6dc1c8"
    second = {"id": "00000000-0000-4000-8000-000000000002", "event_type": "agent.fill", "timestamp": 1762905601,
              "item_id": "00000000-0000-4000-8000-0000000000aa", "result": "ok", "count": 1, "prev_hash": first_hash}
    assert event_hash(first) == first_hash
    assert event_hash(second) == "c524dbc6cca86059dab754117ff3de604fe472e98eef5493f9ca68e39dcf4012"
