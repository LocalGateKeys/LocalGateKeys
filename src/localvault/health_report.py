"""Printable vault health report (sub-plan 12, Task 4): one page of non-secret facts about a vault.

Contains: KDF parameters, unlock factors, backup age and last restore test, devices paired and last sync, access log
verification, breach filter age, build version and hash, licence state. Never an item title, username, URL or
secret: only the vault's public header (``_read_vault_header``) and the counts/ages the caller passes in ``facts``.

The PDF is written by hand (one page, Helvetica, WinAnsi text) so no renderer dependency is needed; A4 or Letter.
A label whose translation Helvetica cannot draw (Japanese, Korean, Chinese) falls back to English.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .i18n import t
from .version import APP_VERSION, BUILD_DATE

PAGE_SIZES = {"a4": (595, 842), "letter": (612, 792)}
MAX_LINES = 40

# English fallbacks (also the en.json values) for labels Helvetica cannot draw in the current language.
LABELS = {
    "healthReport.title": "LocalGateKeys vault health report",
    "healthReport.generated": "Generated",
    "healthReport.kdf": "Key derivation",
    "healthReport.kdfValue": "Argon2id, {memory} MiB memory, {time} passes, {lanes} lanes",
    "healthReport.factors": "Unlock factors",
    "healthReport.backupAge": "Newest backup",
    "healthReport.restoreTest": "Last restore test",
    "healthReport.devices": "Devices paired",
    "healthReport.lastSync": "Last sync",
    "healthReport.accessLog": "Access log verification",
    "healthReport.breachFilter": "Breach filter age",
    "healthReport.build": "Build",
    "healthReport.licence": "Licence",
    "healthReport.unknown": "not recorded",
    "healthReport.noSecrets": "This report holds no passwords, item names or other secrets.",
}


def _label(key: str, **params: Any) -> str:
    text = t(key, **params)
    if text == key or not _drawable(text):
        text = LABELS[key].format(**params) if params else LABELS[key]
    return text


def _drawable(text: str) -> bool:
    try:
        text.encode("cp1252")
        return True
    except UnicodeEncodeError:
        return False


def _kdf_line(vault_path: Path | None) -> tuple[str, str]:
    from .vault import _header_factor_specs, _read_vault_header

    if vault_path is None:
        return _label("healthReport.unknown"), _label("healthReport.unknown")
    try:
        header, _source = _read_vault_header(Path(vault_path))
        kdf = header.get("kdf", {})
        kdf_text = _label("healthReport.kdfValue", memory=int(kdf["memory_cost_kib"]) // 1024,
                          time=int(kdf["time_cost"]), lanes=int(kdf["parallelism"]))
        kinds = [str(spec.kind) for spec in _header_factor_specs(header)]
        factors = ", ".join(["password", *kinds])
        return kdf_text, factors
    except Exception:  # noqa: BLE001 - a report never fails on one missing fact
        return _label("healthReport.unknown"), _label("healthReport.unknown")


def _build_hash() -> str:
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent
    for path in sorted(root.glob("*.py")):
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def lines(session: Any, settings: Any, *, now: int, facts: Mapping[str, Any] | None = None) -> list[tuple[str, str]]:
    """The report rows ``(label, value)``; ``facts`` holds the ages/counts the app knows (all optional)."""
    del settings
    facts = dict(facts or {})
    unknown = _label("healthReport.unknown")
    kdf_text, factors = _kdf_line(getattr(session, "path", None))

    def fact(name: str) -> str:
        value = facts.get(name)
        return str(value) if value not in (None, "") else unknown

    when = dt.datetime.fromtimestamp(int(now), dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    return [
        (_label("healthReport.generated"), when),
        (_label("healthReport.kdf"), kdf_text),
        (_label("healthReport.factors"), factors),
        (_label("healthReport.backupAge"), fact("backup_age")),
        (_label("healthReport.restoreTest"), fact("restore_test")),
        (_label("healthReport.devices"), fact("devices")),
        (_label("healthReport.lastSync"), fact("last_sync")),
        (_label("healthReport.accessLog"), fact("access_log")),
        (_label("healthReport.breachFilter"), fact("breach_filter_age")),
        (_label("healthReport.build"), f"{APP_VERSION} ({BUILD_DATE}) {_build_hash()}"),
        (_label("healthReport.licence"), fact("licence")),
    ]


def _pdf_text(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def render(session: Any, settings: Any, *, now: int, facts: Mapping[str, Any] | None = None,
           page: str = "a4") -> bytes:
    """One-page PDF bytes of the health report."""
    width, height = PAGE_SIZES[page]
    rows = lines(session, settings, now=now, facts=facts)[:MAX_LINES]
    ops = [b"BT /F2 16 Tf 56 %d Td (" % (height - 72) + _pdf_text(_label("healthReport.title")) + b") Tj ET"]
    y = height - 110
    for label, value in rows:
        ops.append(b"BT /F2 10 Tf 56 %d Td (" % y + _pdf_text(label) + b") Tj ET")
        ops.append(b"BT /F1 10 Tf 230 %d Td (" % y + _pdf_text(value[:70]) + b") Tj ET")
        y -= 20
    ops.append(b"BT /F1 9 Tf 56 %d Td (" % max(56, y - 20) + _pdf_text(_label("healthReport.noSecrets")) + b") Tj ET")
    stream = b"\n".join(ops)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>" % (width, height),
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)
