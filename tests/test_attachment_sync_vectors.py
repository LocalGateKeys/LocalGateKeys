from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from localvault.sync import attachment_sync as a

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "sync" / "attachments" / "vectors.json"
DATA = json.loads(VECTORS.read_text(encoding="utf-8"))


def test_generator_reproduces_the_committed_vectors() -> None:
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "make_attachment_sync_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.render() == VECTORS.read_bytes()


@pytest.mark.parametrize("case", DATA["blobs"], ids=lambda c: c["name"])
def test_blobs_seal_and_open(case: dict) -> None:
    key, data = base64.b64decode(case["key"]), base64.b64decode(case["plaintext"])
    blob = a.seal_blob(key, case["attachment_id"], data)
    assert base64.b64encode(blob).decode() == case["blob"]
    assert a.blob_id(blob) == case["blob_id"]
    assert a.open_blob(blob, a.AttachmentRef.from_value(case["ref"])) == data


@pytest.mark.parametrize("case", DATA["refused_blobs"], ids=lambda c: c["name"])
def test_refused_blobs(case: dict) -> None:
    with pytest.raises(a.AttachmentSyncError) as info:
        a.open_blob(base64.b64decode(case["blob"]), a.AttachmentRef.from_value(case["ref"]))
    assert info.value.reason == case["reason"]


@pytest.mark.parametrize("ref", DATA["refused_refs"])
def test_refused_refs(ref: dict) -> None:
    with pytest.raises(a.AttachmentSyncError):
        a.AttachmentRef.from_value(ref)


def test_lan_messages() -> None:
    case = next(c for c in DATA["blobs"] if c["name"] == "two-buckets")
    download = a.BlobDownload(a.AttachmentRef.from_value(case["ref"]))
    assert a.parse_message(json.loads(DATA["lan"]["blob_get"]))["blob"] == case["blob_id"]
    out = None
    for raw in DATA["lan"]["chunks"]:
        out = download.add(json.loads(raw))
    assert base64.b64encode(out).decode() == case["blob"]
