"""Regression tests for the 2026-10-24 extended audit, importer findings (M-8, L-19, L-11).

The crafted files are scaled-down versions of the audit PoCs: each one used to
build every record (and diagnostic) before the 5,000-record limit applied;
now the readers stop while iterating.  Memory is measured with tracemalloc.
"""
from __future__ import annotations

import base64
import io
import json
import random
import shutil
import time
import tracemalloc
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from localvault.import_workflow import apply_import_plan, normalise_records, plan_records
from localvault.importers import (
    MAX_DIAGNOSTICS,
    MAX_JSON_BYTES,
    MAX_RECORDS,
    ImportedRecord,
    ImportFormatError,
    bitwarden,
    cap_diagnostics,
    kdbx,
    onepassword,
    protonpass,
)
from localvault.importers.detect import load_records
from localvault.vault import create_vault

MASTER = "synthetic importer secfix master password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
KDBX_PASSWORD = "synthetic-kdbx-password"
FAST_KDF = {"rounds": 1}
MiB = 1024 * 1024


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"secfix-imp-{request.node.name[:40]}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _measure(action: Callable[[], Any]) -> tuple[BaseException | None, float, int]:
    """(raised exception, seconds, tracemalloc peak bytes) of ``action``."""
    tracemalloc.start()
    started = time.perf_counter()
    error: BaseException | None = None
    try:
        action()
    except Exception as exc:  # noqa: BLE001 - returned to the test
        error = exc
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return error, elapsed, peak


def _zip(member: str, body: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(member, body)
    return buffer.getvalue()


# --------------------------------------------------------------------------- M-8: JSON bombs
def _empty_items(count: int, item: bytes = b"{}") -> bytes:
    return b",".join([item] * count)


@pytest.mark.parametrize("kind", ["proton", "proton-nondict", "1pux", "bitwarden"])
def test_json_item_flood_stops_early_with_bounded_memory(kind: str) -> None:
    count = 600_000  # ~1.8 MiB of JSON; the old readers built 600,000 records (~500 MB)
    if kind == "proton":
        source = _zip("Proton Pass/data.json", b'{"vaults":{"x":{"items":[' + _empty_items(count) + b"]}}}")
        loader: Callable[[bytes], Any] = protonpass.load_protonpass_json
    elif kind == "proton-nondict":
        source = _zip("Proton Pass/data.json", b'{"vaults":{"x":{"items":[' + _empty_items(count, b"0") + b"]}}}")
        loader = protonpass.load_protonpass_json
    elif kind == "1pux":
        source = _zip("export.data", b'{"accounts":[{"vaults":[{"items":[' + _empty_items(count) + b"]}]}]}")
        loader = onepassword.load_1pux
    else:
        source = b'{"items":[' + _empty_items(count) + b"]}"
        loader = bitwarden.load_bitwarden_json
    error, elapsed, peak = _measure(lambda: loader(source))
    assert isinstance(error, ImportFormatError) and "5,000" in str(error)
    assert peak < 120 * MiB, f"peak {peak // MiB} MiB"
    assert elapsed < 10


def test_trashed_and_malformed_items_count_towards_the_limit() -> None:
    trashed = b'{"state":2,"data":{"type":"note","metadata":{"name":"t"}}}'
    note = b'{"data":{"type":"note","metadata":{"name":"n"}}}'
    at_limit = b'{"vaults":{"x":{"items":[' + _empty_items(MAX_RECORDS - 1, note) + b"," + trashed + b"]}}}"
    result = protonpass.load_protonpass_json(at_limit)
    assert len(result.records) == MAX_RECORDS - 1
    over = b'{"vaults":{"x":{"items":[' + _empty_items(MAX_RECORDS, trashed) + b",0]}}}"
    with pytest.raises(ImportFormatError, match="5,000"):
        protonpass.load_protonpass_json(over)


def test_bitwarden_refuses_an_oversized_list_before_converting(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(bitwarden, "item_to_record", lambda *args, **kwargs: calls.append(1))
    document = {"items": [{"deletedDate": "2026-01-01"}] * (MAX_RECORDS + 1)}
    with pytest.raises(ImportFormatError, match="5,000"):
        bitwarden.records_from_document(document, source_format="bitwarden-json")
    assert calls == []


@pytest.mark.parametrize("kind", ["proton", "1pux"])
def test_decompressed_json_is_capped_at_16_mib(kind: str) -> None:
    body = b" " * (MAX_JSON_BYTES + 1)  # compresses to a few KiB
    if kind == "proton":
        with pytest.raises(ImportFormatError, match="too large"):
            protonpass.read_data_json(_zip("Proton Pass/data.json", body))
    else:
        with pytest.raises(ImportFormatError, match="too large"):
            onepassword.read_export_data(_zip("export.data", body))


def test_cap_diagnostics_keeps_first_fifty_and_counts_the_rest() -> None:
    messages = [f"message {index}" for index in range(120)]
    capped = cap_diagnostics(messages)
    assert capped[:MAX_DIAGNOSTICS] == messages[:MAX_DIAGNOSTICS]
    assert capped[-1] == "...and 70 more messages."
    assert len(capped) == MAX_DIAGNOSTICS + 1
    assert cap_diagnostics(messages[:3]) == messages[:3]


def test_load_records_caps_diagnostics(case_dir: Path) -> None:
    path = case_dir / "bitwarden.json"
    path.write_text(json.dumps({"items": [{"deletedDate": "2026-01-01"}] * 400 + [7] * 400}), encoding="utf-8")
    result = load_records(path)
    assert len(result.diagnostics) == MAX_DIAGNOSTICS + 1
    assert result.diagnostics[-1] == "...and 750 more messages."


# --------------------------------------------------------------------------- M-8: KDBX
def _keepass_xml(body: bytes) -> bytes:
    return b"<KeePassFile><Root><Group><Name>Root</Name>" + body + b"</Group></Root></KeePassFile>"


def test_kdbx_entry_flood_is_refused_in_the_expat_pre_pass(case_dir: Path) -> None:
    xml = _keepass_xml(b"<Entry/>" * 300_000)  # 2.3 MiB; ~360 MiB as ElementTree + records before
    blob = kdbx.write_kdbx([], KDBX_PASSWORD, version=4, kdf="aes-kdf", kdf_params=FAST_KDF, xml=xml)
    path = case_dir / "flood.kdbx"
    path.write_bytes(blob)
    error, elapsed, peak = _measure(lambda: load_records(path, password=KDBX_PASSWORD))
    assert isinstance(error, ImportFormatError) and "5,000" in str(error)
    assert peak < 40 * MiB, f"peak {peak // MiB} MiB"
    assert elapsed < 10


def test_kdbx_entry_limit_counts_recycle_bin_but_not_history() -> None:
    history = b"<History>" + b"<Entry/>" * 30 + b"</History>"
    ok = _keepass_xml(b"<Entry><String><Key>Title</Key><Value>a</Value></String>" + history + b"</Entry>"
                      + b"<Entry/>" * (MAX_RECORDS - 1))
    assert len(kdbx.load_keepass_xml(ok).records) == MAX_RECORDS
    with pytest.raises(ImportFormatError, match="5,000"):
        kdbx.load_keepass_xml(_keepass_xml(b"<Entry/>" * (MAX_RECORDS + 1)))


def test_kdbx_history_and_element_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kdbx, "MAX_HISTORY_ENTRIES", 10)
    with pytest.raises(ImportFormatError, match="historical"):
        kdbx.load_keepass_xml(_keepass_xml(b"<Entry><History>" + b"<Entry/>" * 11 + b"</History></Entry>"))
    monkeypatch.setattr(kdbx, "MAX_XML_ELEMENTS", 100)
    with pytest.raises(ImportFormatError, match="too many elements"):
        kdbx.load_keepass_xml(_keepass_xml(b"<Entry>" + b"<X/>" * 100 + b"</Entry>"))


# --------------------------------------------------------------------------- L-19: KDBX inner stream
class _ReferenceStream:
    """The pre-fix byte-wise implementation, kept as an oracle for the keystream order."""

    def __init__(self, stream_id: int, key: bytes) -> None:
        self._inner = kdbx._KeyStream(stream_id, key)
        self._buffer = b""

    def process(self, data: bytes) -> bytes:
        while len(self._buffer) < len(data):
            self._buffer += self._inner._generate(64)
        stream, self._buffer = self._buffer[:len(data)], self._buffer[len(data):]
        return bytes(a ^ b for a, b in zip(data, stream, strict=True))


@pytest.mark.parametrize("stream_id", [kdbx.STREAM_ARC4, kdbx.STREAM_SALSA20, kdbx.STREAM_CHACHA20])
def test_keystream_matches_the_byte_wise_reference(stream_id: int) -> None:
    rng = random.Random(stream_id)  # noqa: S311 - deterministic test data
    key = bytes(rng.randrange(256) for _ in range(32))
    fast, reference = kdbx._KeyStream(stream_id, key), _ReferenceStream(stream_id, key)
    for size in (1, 7, 64, 65, 300, 4096, 5000, 3):
        data = bytes(rng.randrange(256) for _ in range(size))
        assert fast.process(data) == reference.process(data)


@pytest.mark.parametrize("version", [3, 4])
def test_large_protected_value_round_trips_in_linear_time(case_dir: Path, version: int) -> None:
    password = "p" * (256 * 1024)
    record = ImportedRecord(kind="login", title="big", username="u", password=password, urls=["https://a.example"])
    path = case_dir / f"big{version}.kdbx"
    path.write_bytes(kdbx.write_kdbx([record], KDBX_PASSWORD, version=version, kdf="aes-kdf", kdf_params=FAST_KDF))
    started = time.perf_counter()
    result = load_records(path, password=KDBX_PASSWORD)
    assert time.perf_counter() - started < 10
    assert result.records[0].password == password


def test_oversized_protected_values_are_refused_before_decrypting(case_dir: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    records = [ImportedRecord(kind="login", title=f"r{index}", username="u", password="p" * 3000,
                              urls=["https://a.example"]) for index in range(4)]
    path = case_dir / "v3.kdbx"
    path.write_bytes(kdbx.write_kdbx(records, KDBX_PASSWORD, version=3, kdf="aes-kdf", kdf_params=FAST_KDF))
    generated: list[int] = []
    original = kdbx._KeyStream.process

    def spy(self: Any, data: bytes) -> bytes:
        generated.append(len(data))
        return original(self, data)

    monkeypatch.setattr(kdbx._KeyStream, "process", spy)
    monkeypatch.setattr(kdbx, "MAX_PROTECTED_VALUE_BYTES", 1024)
    with pytest.raises(ImportFormatError, match="protected value .* too large"):
        load_records(path, password=KDBX_PASSWORD)
    assert generated == []
    monkeypatch.setattr(kdbx, "MAX_PROTECTED_VALUE_BYTES", 1024 * 1024)
    monkeypatch.setattr(kdbx, "MAX_SLOW_STREAM_TOTAL_BYTES", 8000)  # Salsa20 (KDBX 3) budget
    with pytest.raises(ImportFormatError, match="protected values .* too large"):
        load_records(path, password=KDBX_PASSWORD)


# --------------------------------------------------------------------------- L-11: preview limits
def test_preview_rows_respect_item_schema_limits_and_apply(case_dir: Path) -> None:
    records = [
        # seed 911: an invalid 5,000-digit card number became a 5,000-character note field
        ImportedRecord(kind="card", title="Card", card={"number": "4" * 5000, "cvv": "1" * 5000}),
        ImportedRecord(kind="login", title="No site", username="u", password="p" * 5000,
                       custom_fields=[{"name": "n" * 300, "value": "v" * 5000}]),
        ImportedRecord(kind="identity", title="Identity", identity={"name": "x" * 9000},
                       custom_fields=[{"name": "k" * 300, "value": "v"}]),
        ImportedRecord(kind="note", title="Note", custom_fields=[{"name": f"f{index}", "value": "v"}
                                                                 for index in range(50)]),
    ]
    rows, issues = normalise_records(records)
    for row in rows:
        for record in (row.record, row.extra):
            if record is None:
                continue
            assert len(record.custom_fields) <= 50
            assert all(len(field["name"]) <= 100 and len(field["value"]) <= 4096 for field in record.custom_fields)
    assert any("Card number" in issue for issue in issues)
    session = create_vault(case_dir / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    plan = plan_records(session, records)
    plan.review()
    assert apply_import_plan(session, plan) >= len(records)


def test_plan_diagnostics_are_capped(case_dir: Path) -> None:
    session = create_vault(case_dir / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    records = [ImportedRecord(kind="login", title=f"r{index}", username="u", password="p") for index in range(200)]
    plan = plan_records(session, records, diagnostics=[f"source {index}" for index in range(80)])
    assert len(plan.diagnostics) <= 2 * (MAX_DIAGNOSTICS + 1) + 1
    assert "...and 30 more messages." in plan.diagnostics
    assert any(issue.startswith("...and 150 more") for issue in plan.diagnostics)


@pytest.mark.parametrize("url", ["https://[::1", "https://ex]ample.com/", "https://example.com:99999/"])
def test_canonical_origin_for_raises_origin_error_only(url: str) -> None:
    from localvault.import_workflow import canonical_origin_for
    from localvault.origin import OriginError

    with pytest.raises(OriginError):
        canonical_origin_for(url)


def test_malformed_or_refused_urls_are_rejected_per_row(case_dir: Path) -> None:
    bad = ["https://[::1", "https://[::1/login", "https://exa%41mple.com/", "https://exa|mple.com/",
           "https://[fe80::1%25eth0]/", "https://[::ffff:127.0.0.1]/", "https://example.com../"]
    records = [ImportedRecord(kind="login", title=f"bad {index}", username="u", password="p", urls=[url])
               for index, url in enumerate(bad, 1)]
    records.append(ImportedRecord(kind="login", title="good", username="u", password="p",
                                  urls=["https://good.example/login"]))
    rows, issues = normalise_records(records)
    assert [row.kind for row in rows] == ["note"] * len(bad) + ["login"]
    assert sum("usable website address" in issue for issue in issues) == len(bad)
    session = create_vault(case_dir / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    plan = plan_records(session, records)
    plan.review()
    assert apply_import_plan(session, plan) == len(records)


def test_protected_value_base64_bound_matches_decoded_size() -> None:
    # The size check runs on the Base64 text: len // 4 * 3 is never below the decoded length - 3.
    for size in range(0, 40):
        text = base64.b64encode(b"x" * size).decode()
        assert len(text) // 4 * 3 >= size
