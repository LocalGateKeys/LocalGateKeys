"""Optional, local-only OCR derivatives and deliberate document search.

The service keeps extracted text in encrypted sidecars and exposes it only
through an explicit, lease-bound content-search call.  It never changes the
metadata search projection.  A real adapter must run inside an enforceable
no-egress boundary (the packaged Windows implementation is expected to use an
AppContainer without network capabilities); the test adapter is deliberately
injected and never enabled by default.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import VaultError, VaultLockedError

MAX_OCR_INPUT = 25 * 1024 * 1024
MAX_OCR_PAGES = 100
MAX_OCR_PAGE_SECONDS = 30
MAX_OCR_JOB_SECONDS = 5 * 60
MAX_OCR_TEXT = 2 * 1024 * 1024
MAX_OCR_STORE = 200 * 1024 * 1024
MAX_CONTENT_QUERY = 256
MAX_CONTENT_MATCHES = 100
MAX_CONTENT_MATCHES_PER_PAGE = 20
MAX_SNIPPET = 240
OCR_VERSION = 1
MAX_OCR_MANIFEST_ROWS = MAX_OCR_STORE // 1024


@dataclass(frozen=True)
class NoEgressProof:
    """Evidence supplied by an adapter runner for its process boundary.

    A caller supplied boolean is not a boundary.  The runner owns this proof
    and must report the mechanism, the absence of network capabilities, and a
    denied outbound probe.  ``SubprocessNoEgressRunner`` accepts only a proof
    that passes these checks; a platform runner can add stronger OS-specific
    validation before constructing it.
    """

    mechanism: str
    network_capabilities: tuple[str, ...] = ()
    outbound_probe: str = "denied"
    process_isolated: bool = True

    def is_enforceable(self) -> bool:
        if not isinstance(self.mechanism, str) or not isinstance(self.outbound_probe, str):
            return False
        mechanism = self.mechanism.strip().casefold()
        return bool(mechanism) and type(self.process_isolated) is bool and self.process_isolated \
            and not self.network_capabilities and self.outbound_probe.strip().casefold() == "denied"

    def require_enforceable(self) -> None:
        if not self.is_enforceable():
            raise OcrUnavailable("OCR requires an enforceable no-egress boundary proof")


@dataclass(frozen=True)
class OcrResult:
    """Bounded adapter output with an optional preflight page count."""

    text: str
    pages: int | None = None


class NoEgressRunner(Protocol):
    """Runner contract for a fixed-argv adapter process."""

    @property
    def proof(self) -> NoEgressProof: ...

    def run(self, argv: Sequence[str], *, timeout: float,
            cancel: Callable[[], bool] | None = None) -> subprocess.CompletedProcess[str]: ...


class SubprocessNoEgressRunner:
    """Fixed-argv runner used only after a reviewed boundary is configured.

    This class does not manufacture an AppContainer or firewall rule.  Its
    proof is therefore an explicit input, and an absent/invalid proof fails
    closed.  The packaged Windows runner can implement the same protocol and
    construct a proof after applying the OS boundary.
    """

    def __init__(self, proof: NoEgressProof) -> None:
        self.proof = proof

    def run(self, argv: Sequence[str], *, timeout: float,
            cancel: Callable[[], bool] | None = None) -> subprocess.CompletedProcess[str]:
        self.proof.require_enforceable()
        if not argv or any(not isinstance(value, str) or not value for value in argv):
            raise OcrError("OCR runner arguments are malformed")
        if not os.path.isabs(argv[0]):
            # A bare name would be resolved through the application and current
            # directories first, letting a planted binary run as the OCR helper.
            raise OcrError("OCR runner executable must be an absolute path")
        started = time.monotonic()
        process = subprocess.Popen(
            list(argv), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            while process.poll() is None:
                if _cancelled(cancel):
                    process.kill()
                    process.communicate()
                    raise OcrCancelled("OCR was cancelled")
                if time.monotonic() - started > timeout:
                    process.kill()
                    process.communicate()
                    raise subprocess.TimeoutExpired(list(argv), timeout)
                time.sleep(min(0.05, max(0.001, timeout / 100)))
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


class OcrError(VaultError):
    """Bounded OCR or protected content-search failure."""


class OcrUnavailable(OcrError):
    pass


class OcrCancelled(OcrError):
    pass


class OcrAdapter(Protocol):
    def extract(self, data: bytes, *, mime_type: str,
                cancel: Callable[[], bool] | None = None) -> str | OcrResult: ...


@dataclass(frozen=True)
class OcrMatch:
    item_id: str
    attachment_id: str
    snippet: str
    page: int | None = None


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any) -> bytes:
    if not isinstance(value, str):
        raise OcrError("OCR derivative encoding is malformed")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise OcrError("OCR derivative encoding is malformed") from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _cancelled(cancel: Callable[[], bool] | threading.Event | None) -> bool:
    if cancel is None:
        return False
    return bool(cancel.is_set() if hasattr(cancel, "is_set") else cancel())


def _require_runner_proof(runner: NoEgressRunner | None) -> NoEgressProof:
    if runner is None:
        raise OcrUnavailable("OCR is disabled until a no-egress runner is configured")
    proof = getattr(runner, "proof", None)
    if not isinstance(proof, NoEgressProof):
        raise OcrUnavailable("OCR runner did not provide a no-egress proof")
    proof.require_enforceable()
    return proof


def _pdf_page_count(data: bytes) -> int:
    """Count only passive PDF page objects without parsing or executing PDF code."""
    if not isinstance(data, bytes) or len(data) < 5 or not data.startswith(b"%PDF-"):
        raise OcrError("PDF header is malformed")
    # Active content and remote references are rejected before any adapter is
    # started.  The parser is deliberately conservative and byte oriented.
    if re.search(rb"/(?:JavaScript|JS|Launch|OpenAction|AA|RichMedia|URI)\b", data):
        raise OcrError("PDF contains active or remote content")
    pages = len(re.findall(rb"/Type\s*/Page(?!s)\b", data))
    if pages == 0:
        count_match = re.search(rb"/Type\s*/Pages\b[\s\S]{0,2048}?/Count\s+(\d+)", data)
        if count_match is None:
            raise OcrError("PDF page tree is malformed")
        try:
            pages = int(count_match.group(1))
        except (TypeError, ValueError) as exc:
            raise OcrError("PDF page count is malformed") from exc
    if pages < 0 or pages > MAX_OCR_PAGES:
        raise OcrError("PDF exceeds the bounded page count")
    return pages


class _FixedCommandAdapter:
    """Shared bounded temporary-file and fixed-argv handling."""

    _suffix = ".input"

    def __init__(self, executable: str | Path | None, *, runner: NoEgressRunner | None,
                 timeout: float = MAX_OCR_JOB_SECONDS,
                 input_dir: str | Path | None = None) -> None:
        self.executable = str(executable) if executable is not None else ""
        self.runner = runner
        self.timeout = max(0.01, min(float(timeout), float(MAX_OCR_JOB_SECONDS)))
        self.input_dir = Path(input_dir).resolve() if input_dir is not None else None

    @property
    def boundary_proof(self) -> NoEgressProof | None:
        proof = getattr(self.runner, "proof", None)
        return proof if isinstance(proof, NoEgressProof) else None

    def _run(self, data: bytes, *, cancel: Callable[[], bool] | None,
             argv_suffix: Sequence[str]) -> str:
        _require_runner_proof(self.runner)
        if not self.executable:
            raise OcrUnavailable("The local OCR engine is unavailable")
        if not isinstance(data, bytes) or len(data) > MAX_OCR_INPUT:
            raise OcrError("OCR input exceeds the bounded size")
        if _cancelled(cancel):
            raise OcrCancelled("OCR was cancelled")
        if self.input_dir is None:
            raise OcrUnavailable("OCR requires a profile-owned temporary directory")
        self.input_dir.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=".lgk-ocr-", suffix=self._suffix,
                                                 dir=self.input_dir)
        temp = Path(temp_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            completed = self.runner.run(
                [self.executable, str(temp), *argv_suffix],
                timeout=self.timeout,
                cancel=cancel,
            )
        except OcrCancelled:
            raise
        except subprocess.TimeoutExpired as exc:
            raise OcrError("OCR exceeded its job deadline") from exc
        except OcrUnavailable:
            raise
        except OSError as exc:
            raise OcrUnavailable("The local OCR engine is unavailable") from exc
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        if not isinstance(completed, subprocess.CompletedProcess) or completed.returncode != 0:
            raise OcrError("The local OCR adapter rejected the document")
        text = completed.stdout
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_OCR_TEXT:
            raise OcrError("OCR output exceeds the bounded document size")
        return text


class TesseractAdapter(_FixedCommandAdapter):
    """Fixed-argv adapter requiring a proof-bearing no-egress runner.

    ``network_isolation_proven`` remains accepted for source compatibility,
    but it is intentionally ignored for this process adapter.  A runner and
    its proof are required before a child process can start.
    """

    def __init__(self, executable: str | Path, *, network_isolation_proven: bool = False,
                 runner: NoEgressRunner | None = None,
                 proof: NoEgressProof | None = None,
                 timeout: float = MAX_OCR_JOB_SECONDS,
                 input_dir: str | Path | None = None) -> None:
        if runner is None and proof is not None:
            runner = SubprocessNoEgressRunner(proof)
        super().__init__(executable, runner=runner, timeout=timeout, input_dir=input_dir)
        # Kept only for callers that introspect the old option.  It never
        # enables execution and is not consulted by ``extract``.
        self.network_isolation_proven = bool(network_isolation_proven)

    def extract(self, data: bytes, *, mime_type: str,
                cancel: Callable[[], bool] | None = None) -> str:
        del mime_type
        return self._run(data, cancel=cancel, argv_suffix=("stdout", "-l", "eng"))


class PdfAdapter(_FixedCommandAdapter):
    """Optional passive-PDF OCR seam with a dependency-free page preflight.

    The adapter has no built-in PDF renderer.  Without an explicitly selected
    executable and proof-bearing runner it fails closed with ``OcrUnavailable``.
    A configured runner must rasterize or extract only the supplied local path
    using fixed arguments and no remote/active-content handling.
    """

    _suffix = ".pdf"

    def __init__(self, executable: str | Path | None = None, *, runner: NoEgressRunner | None = None,
                 proof: NoEgressProof | None = None,
                 timeout: float = MAX_OCR_JOB_SECONDS,
                 input_dir: str | Path | None = None) -> None:
        if runner is None and proof is not None:
            runner = SubprocessNoEgressRunner(proof)
        super().__init__(executable, runner=runner, timeout=timeout, input_dir=input_dir)

    def preflight(self, data: bytes) -> int:
        pages = _pdf_page_count(data)
        if pages > MAX_OCR_PAGES:
            raise OcrError("PDF exceeds the bounded page count")
        return pages

    def extract(self, data: bytes, *, mime_type: str,
                cancel: Callable[[], bool] | None = None) -> OcrResult:
        if mime_type.casefold() != "application/pdf":
            raise OcrError("PDF adapter requires application/pdf input")
        pages = self.preflight(data)
        text = self._run(data, cancel=cancel, argv_suffix=("stdout", "-l", "eng"))
        return OcrResult(text=text, pages=pages)


class OcrSearchService:
    """Encrypted derivative/index service bound to one unlocked VaultSession."""

    def __init__(self, session: Any, attachment_store: Any, *, adapter: OcrAdapter | None = None,
                 network_isolation_proven: bool = False,
                 page_timeout_seconds: float = MAX_OCR_PAGE_SECONDS,
                 job_timeout_seconds: float = MAX_OCR_JOB_SECONDS) -> None:
        self.session = session
        self.attachments = attachment_store
        self.adapter = adapter
        self.page_timeout_seconds = max(0.01, min(float(page_timeout_seconds), float(MAX_OCR_PAGE_SECONDS)))
        self.job_timeout_seconds = max(0.01, min(float(job_timeout_seconds), float(MAX_OCR_JOB_SECONDS)))
        self.network_isolation_proven = bool(network_isolation_proven)
        self.root = Path(session.path).parent / "OcrDerivatives"
        self.root.mkdir(parents=True, exist_ok=True)
        if isinstance(adapter, (_FixedCommandAdapter,)) and adapter.input_dir is None:
            adapter.input_dir = (self.root / "tmp").resolve()

    def _require(self) -> tuple[dict[str, Any], bytes]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        key = getattr(self.session, "_key", None)
        if not key:
            raise VaultLockedError("Vault key is unavailable")
        return self.session._require_typed_catalog(), bytes(key)

    def _manifest(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        rows = payload.setdefault("ocr_derivatives", [])
        if not isinstance(rows, list) or len(rows) > MAX_OCR_MANIFEST_ROWS:
            raise OcrError("OCR derivative manifest is malformed")
        return rows

    def _require_adapter_boundary(self) -> None:
        if self.adapter is None:
            raise OcrUnavailable("OCR is disabled until a local adapter is configured")
        # Process adapters must prove their own boundary.  The legacy boolean
        # remains a compatibility gate for injected in-process test adapters;
        # it can never authorize Tesseract/PDF child processes.
        if isinstance(self.adapter, _FixedCommandAdapter):
            _require_runner_proof(self.adapter.runner)
            return
        proof = getattr(self.adapter, "boundary_proof", None)
        if isinstance(proof, NoEgressProof):
            proof.require_enforceable()
            return
        if not self.network_isolation_proven:
            raise OcrUnavailable("OCR is disabled until a local no-egress adapter is configured")

    def _preflight_pages(self, adapter: OcrAdapter, raw: bytes, mime_type: str) -> int | None:
        preflight = getattr(adapter, "preflight", None)
        if callable(preflight):
            pages = preflight(raw)
        elif mime_type.casefold() == "application/pdf":
            # Even a test adapter cannot bypass the PDF page/content gate.
            pages = _pdf_page_count(raw)
        else:
            pages = None
        if pages is not None and (type(pages) is not int or pages < 0 or pages > MAX_OCR_PAGES):
            raise OcrError("OCR page count exceeds the bounded limit")
        return pages

    def _extract_bounded(self, raw: bytes, *, mime_type: str,
                         cancel: Callable[[], bool] | threading.Event | None,
                         pages: int | None) -> str:
        adapter = self.adapter
        if adapter is None:
            raise OcrUnavailable("OCR is disabled until a local adapter is configured")
        result: dict[str, Any] = {}
        finished = threading.Event()

        def run() -> None:
            try:
                result["value"] = adapter.extract(
                    raw, mime_type=mime_type, cancel=lambda: _cancelled(cancel) or finished.is_set())
            except Exception as exc:  # noqa: BLE001 - re-raise worker errors on caller thread
                result["error"] = exc
            finally:
                finished.set()

        worker = threading.Thread(target=run, name="localvault-ocr", daemon=True)
        worker.start()
        page_deadline = (self.page_timeout_seconds * max(1, pages)
                         if pages is not None else self.job_timeout_seconds)
        deadline = min(self.job_timeout_seconds, page_deadline)
        worker.join(deadline)
        if worker.is_alive():
            finished.set()
            raise OcrError("OCR exceeded its bounded time limit")
        if _cancelled(cancel):
            raise OcrCancelled("OCR was cancelled")
        if "error" in result:
            error = result["error"]
            if isinstance(error, OcrError):
                raise error
            raise OcrError("OCR adapter failed") from error
        value = result.get("value")
        if isinstance(value, OcrResult):
            if value.pages is not None and (type(value.pages) is not int or
                                             value.pages < 0 or value.pages > MAX_OCR_PAGES):
                raise OcrError("OCR adapter returned an out-of-bounds page count")
            text = value.text
        else:
            text = value
        if not isinstance(text, str):
            raise OcrError("OCR adapter returned malformed text")
        if len(text.encode("utf-8")) > MAX_OCR_TEXT:
            raise OcrError("OCR output exceeds the bounded document size")
        return text

    def _sidecar_path(self, derivative_id: str) -> Path:
        try:
            derivative_id = str(uuid.UUID(derivative_id))
        except (ValueError, TypeError, AttributeError):
            raise OcrError("OCR derivative ID is malformed") from None
        return self.root / f"{derivative_id}.blob"

    def _current_source(self, payload: dict[str, Any], item_id: str,
                        attachment_id: str, source_revision: int) -> dict[str, Any]:
        """Require a live document and an exact revision/attachment match."""
        item = next((row for row in payload.get("items", [])
                     if isinstance(row, dict) and row.get("id") == item_id), None)
        if not isinstance(item, dict) or item.get("kind") != "document":
            raise OcrError("OCR source document was not found")
        typed = item.get("payload")
        if not isinstance(typed, dict) or typed.get("attachment_id") != attachment_id:
            raise OcrError("OCR source attachment does not match the document")
        if type(source_revision) is not int or source_revision != item.get("revision"):
            raise OcrError("OCR source revision is stale")
        return item

    def index(self, item_id: str, attachment_id: str, *, source_revision: int,
              mime_type: str, cancel: Callable[[], bool] | threading.Event | None = None) -> dict[str, Any]:
        payload, key = self._require()
        self._require_adapter_boundary()
        self._current_source(payload, item_id, attachment_id, source_revision)
        raw = self.attachments.read_bytes(attachment_id, cancel=cancel)
        if len(raw) > MAX_OCR_INPUT:
            raise OcrError("OCR input exceeds the bounded size")
        if _cancelled(cancel):
            raise OcrCancelled("OCR was cancelled")
        pages = self._preflight_pages(self.adapter, raw, mime_type)
        text = self._extract_bounded(raw, mime_type=mime_type, cancel=cancel, pages=pages)
        # A document can be replaced while an OCR process is running. Recheck
        # before publication so a stale derivative can never become current.
        self._current_source(payload, item_id, attachment_id, source_revision)
        derivative_id = str(uuid.uuid4())
        source_hash = hashlib.sha256(raw).hexdigest()
        header = {"version": OCR_VERSION, "id": derivative_id, "item_id": item_id,
                  "attachment_id": attachment_id, "source_hash": source_hash,
                  "source_revision": source_revision}
        if pages is not None:
            header["page_count"] = pages
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), _canonical(header))
        blob = _canonical({"header": header, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)})
        if sum(int(row.get("size", 0)) for row in self._manifest(payload)) + len(blob) > MAX_OCR_STORE:
            raise OcrError("OCR derived-data quota exceeded")
        temp = self.root / f".{derivative_id}.tmp"
        sidecar = self._sidecar_path(derivative_id)
        try:
            with temp.open("xb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, sidecar)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise OcrError("Could not publish the encrypted OCR derivative") from exc
        finally:
            temp.unlink(missing_ok=True)
        extractor = "pdf-v1" if isinstance(self.adapter, PdfAdapter) else (
            "tesseract-v1" if isinstance(self.adapter, TesseractAdapter) else "adapter-v1")
        row = {**header, "extractor_version": extractor, "size": len(blob),
               "created_at": int(time.time())}
        self._manifest(payload)[:] = [r for r in self._manifest(payload)
                                      if r.get("item_id") != item_id or r.get("attachment_id") != attachment_id]
        self._manifest(payload).append(row)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            self._sidecar_path(derivative_id).unlink(missing_ok=True)
            self._manifest(payload)[:] = [r for r in self._manifest(payload) if r is not row]
            raise
        return {k: row[k] for k in ("id", "item_id", "attachment_id", "source_revision", "source_hash", "size")}

    def purge(self, *, item_id: str | None = None) -> int:
        payload, _ = self._require()
        rows = self._manifest(payload)
        keep = [row for row in rows if item_id is None or row.get("item_id") != item_id]
        removed = [row for row in rows if row not in keep]
        for row in removed:
            try:
                self._sidecar_path(str(row["id"])).unlink(missing_ok=True)
            except OSError:
                pass
        rows[:] = keep
        if removed:
            self.session.save()
        return len(removed)

    def search(self, query: str, *, item_ids: Iterable[str] | None = None,
               lease: Any | None = None) -> tuple[OcrMatch, ...]:
        payload, key = self._require()
        if lease is not None and hasattr(self.session, "require"):
            self.session.require(lease)
        if not isinstance(query, str) or not query.strip() or len(query) > MAX_CONTENT_QUERY:
            raise OcrError("Content query is empty or exceeds the bound")
        wanted: set[str] = set()
        if item_ids is not None:
            for count, value in enumerate(item_ids):
                if count >= MAX_CONTENT_MATCHES:
                    raise OcrError("Content result scope exceeds the bound")
                if not isinstance(value, str) or len(value) > 128:
                    raise OcrError("Content result scope is malformed")
                wanted.add(value)
        result: list[OcrMatch] = []
        for row in list(self._manifest(payload)):
            if wanted and row.get("item_id") not in wanted:
                continue
            try:
                item_id = str(row.get("item_id"))
                attachment_id = str(row.get("attachment_id"))
                self._current_source(payload, item_id, attachment_id,
                                     int(row.get("source_revision")))
                source = self.attachments.read_bytes(attachment_id)
                if len(source) > MAX_OCR_INPUT or hashlib.sha256(source).hexdigest() != row.get("source_hash"):
                    continue
            except (OcrError, TypeError, ValueError):
                # Stale derivatives are never searchable. They remain
                # removable by purge/reindex and do not widen the projection.
                continue
            try:
                blob = json.loads(self._sidecar_path(str(row["id"])).read_text(encoding="utf-8"))
                header = blob["header"]
                nonce = _b64d(blob["nonce"])
                text = AESGCM(key).decrypt(nonce, _b64d(blob["ciphertext"]), _canonical(header)).decode("utf-8")
            except (OSError, KeyError, ValueError, InvalidTag, UnicodeError) as exc:
                raise OcrError("OCR derivative authentication failed") from exc
            if len(text.encode("utf-8")) > MAX_OCR_TEXT:
                raise OcrError("OCR derivative exceeds the bounded document size")
            if query.casefold() not in text.casefold():
                continue
            offset = text.casefold().find(query.casefold())
            start = max(0, offset - MAX_SNIPPET // 2)
            snippet = text[start:start + MAX_SNIPPET]
            result.append(OcrMatch(str(row["item_id"]), str(row["attachment_id"]), snippet, None))
            if len(result) >= MAX_CONTENT_MATCHES:
                break
        if lease is not None and hasattr(self.session, "require"):
            self.session.require(lease)
        return tuple(result)


__all__ = [
    "MAX_CONTENT_MATCHES",
    "MAX_CONTENT_QUERY",
    "MAX_OCR_INPUT",
    "MAX_OCR_JOB_SECONDS",
    "MAX_OCR_PAGES",
    "MAX_OCR_PAGE_SECONDS",
    "MAX_OCR_STORE",
    "MAX_OCR_TEXT",
    "NoEgressProof",
    "NoEgressRunner",
    "OcrCancelled",
    "OcrError",
    "OcrMatch",
    "OcrResult",
    "OcrSearchService",
    "OcrUnavailable",
    "PdfAdapter",
    "SubprocessNoEgressRunner",
    "TesseractAdapter",
]
