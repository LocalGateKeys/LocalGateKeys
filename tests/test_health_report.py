from __future__ import annotations

from pathlib import Path

import pytest

from localvault import health_report, i18n
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
TITLE = "Secret Bank Of Nowhere"


@pytest.fixture()
def session(tmp_path: Path):
    s = create_vault(tmp_path / "vault.json", "synthetic health master 01", kdf_overrides=KDF)
    s.upsert_web(origin="https://bank.example.test", username="alice-user", password="synthetic-pw-xyz", label=TITLE)
    yield s
    s.lock()


@pytest.mark.parametrize("page", ["a4", "letter"])
def test_renders_a_one_page_pdf_with_kdf_memory(session, page) -> None:
    pdf = health_report.render(session, None, now=1_800_000_000, page=page,
                               facts={"backup_age": "2 days", "devices": 3})
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert pdf.count(b"/Type /Page ") == 1
    assert b"8 MiB" in pdf
    assert b"2 days" in pdf


def test_contains_no_title_or_secret(session) -> None:
    pdf = health_report.render(session, None, now=1_800_000_000)
    for needle in (TITLE, "alice-user", "synthetic-pw-xyz", "bank.example.test"):
        assert needle.encode() not in pdf


@pytest.mark.parametrize("lang", ["ja", "de", "zh-Hans"])
def test_every_language_draws(session, lang) -> None:
    i18n.set_language(lang)
    try:
        rows = health_report.lines(session, None, now=0)
        assert all(health_report._drawable(label) for label, _ in rows)
        assert len(rows) <= health_report.MAX_LINES
    finally:
        i18n.set_language("en")
