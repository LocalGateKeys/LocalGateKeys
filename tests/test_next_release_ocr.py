from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from localvault.attachments import AttachmentStore, DocumentService
from localvault.ocr_search import (
    MAX_OCR_TEXT,
    NoEgressProof,
    OcrError,
    OcrResult,
    OcrSearchService,
    OcrUnavailable,
    PdfAdapter,
    TesseractAdapter,
)
from localvault.vault import VaultLockedError, create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


class FakeAdapter:
    def extract(self, data: bytes, *, mime_type: str, cancel=None) -> str:
        return data.decode("utf-8")


class OversizedAdapter:
    def extract(self, data: bytes, *, mime_type: str, cancel=None) -> str:
        return "x" * (MAX_OCR_TEXT + 1)


class SlowAdapter:
    def extract(self, data: bytes, *, mime_type: str, cancel=None) -> str:
        time.sleep(0.2)
        return data.decode("utf-8")


class TooManyPagesAdapter:
    def extract(self, data: bytes, *, mime_type: str, cancel=None) -> OcrResult:
        return OcrResult(data.decode("utf-8"), pages=101)


class FakeRunner:
    proof = NoEgressProof("test-no-egress")

    def run(self, argv, *, timeout, cancel=None):
        return subprocess.CompletedProcess(
            argv, 0, Path(argv[1]).read_text(encoding="utf-8"), ""
        )


def test_ocr_is_opt_in_and_encrypted(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"private renewal reference")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    attachment_id = item["payload"]["attachment_id"]
    service = OcrSearchService(session, store, adapter=FakeAdapter(), network_isolation_proven=True)
    row = service.index(item_id, attachment_id, source_revision=item["revision"], mime_type="text/plain")
    assert service.search("renewal")[0].item_id == item_id
    sidecar = service.root / f"{row['id']}.blob"
    assert b"private renewal reference" not in sidecar.read_bytes()
    session.lock()
    with pytest.raises(VaultLockedError):
        service.search("renewal")


def test_ocr_requires_proven_no_egress_and_bounds_query(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"private")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    attachment_id = item["payload"]["attachment_id"]
    disabled = OcrSearchService(session, store, adapter=FakeAdapter(), network_isolation_proven=False)
    with pytest.raises(OcrUnavailable):
        disabled.index(item_id, attachment_id, source_revision=item["revision"], mime_type="text/plain")
    enabled = OcrSearchService(session, store, adapter=FakeAdapter(), network_isolation_proven=True)
    enabled.index(item_id, attachment_id, source_revision=item["revision"], mime_type="text/plain")
    with pytest.raises(OcrError):
        enabled.search("x" * 257)


def test_process_adapter_ignores_legacy_boolean_without_runner(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"private")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    adapter = TesseractAdapter("tesseract", network_isolation_proven=True)
    service = OcrSearchService(session, store, adapter=adapter, network_isolation_proven=True)
    with pytest.raises(OcrUnavailable):
        service.index(item_id, item["payload"]["attachment_id"],
                     source_revision=item["revision"], mime_type="text/plain")


def test_process_adapter_requires_and_consumes_proof_bearing_runner(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"proof-bound renewal")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    adapter = TesseractAdapter("local-tesseract", runner=FakeRunner())
    service = OcrSearchService(session, store, adapter=adapter)
    service.index(item_id, item["payload"]["attachment_id"],
                 source_revision=item["revision"], mime_type="text/plain")
    assert service.search("renewal")[0].item_id == item_id


def test_pdf_adapter_fails_closed_and_rejects_malformed_or_oversized_pages() -> None:
    adapter = PdfAdapter()
    with pytest.raises(OcrError):
        adapter.preflight(b"not a pdf")
    with pytest.raises(OcrUnavailable):
        adapter.extract(b"%PDF-1.7\n/Type /Pages /Count 0", mime_type="application/pdf")
    oversized = b"%PDF-1.7\n" + b"\n".join(
        b"<< /Type /Page >>" for _ in range(101)
    )
    with pytest.raises(OcrError):
        adapter.preflight(oversized)


def test_ocr_rejects_adapter_output_and_result_page_bounds(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"private")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    attachment_id = item["payload"]["attachment_id"]
    for adapter in (OversizedAdapter(), TooManyPagesAdapter()):
        service = OcrSearchService(session, store, adapter=adapter,
                                   network_isolation_proven=True)
        with pytest.raises(OcrError):
            service.index(item_id, attachment_id, source_revision=item["revision"],
                         mime_type="text/plain")


def test_ocr_enforces_bounded_adapter_time(workspace_tmp: Path) -> None:
    session = create_vault(workspace_tmp / "vault.json", "synthetic master", kdf_overrides=TEST_KDF)
    store = AttachmentStore(session)
    source = workspace_tmp / "invoice.txt"
    source.write_bytes(b"private")
    item_id = DocumentService(session).create(source, mime_type="text/plain")
    item = session.item_service.get_item_for_edit(item_id)
    service = OcrSearchService(session, store, adapter=SlowAdapter(),
                               network_isolation_proven=True, job_timeout_seconds=0.01)
    with pytest.raises(OcrError, match="time limit"):
        service.index(item_id, item["payload"]["attachment_id"],
                     source_revision=item["revision"], mime_type="text/plain")


def test_subprocess_runner_refuses_bare_executable_name() -> None:
    from localvault.ocr_search import SubprocessNoEgressRunner

    runner = SubprocessNoEgressRunner(NoEgressProof("test-no-egress"))
    with pytest.raises(OcrError, match="absolute path"):
        runner.run(["tesseract.exe", "in.png", "stdout"], timeout=1)
