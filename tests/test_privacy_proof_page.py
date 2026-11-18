"""Privacy proof page service (feature pack 2026-11-15, section 5)."""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault import net_ledger, privacy_proof
from localvault.api.result import ApiError
from localvault.app.privacy_page import PrivacyProofService
from localvault.sync import vault_bridge


class _Session:
    def all_entries(self):
        return [{"title": "secret site"}, {"title": "other"}]

    items = SimpleNamespace(list_items=lambda: [{"kind": "note"}])


class _Controller:
    def __init__(self, unlocked=True):
        self._unlocked = unlocked
        self.session = _Session()
        self.guard = SimpleNamespace(lease=lambda: "lease")
        self.settings = SimpleNamespace(strict_offline_mode=True, breach_check_enabled=False)

    def is_unlocked(self):
        return self._unlocked

    def require_lease(self, lease):
        assert lease == "lease"


class _Dialogs:
    def __init__(self, target):
        self.target = target
        self.asked = None

    def save_file(self, title, default):
        self.asked = default
        return self.target


@pytest.fixture(autouse=True)
def _ledger():
    net_ledger._reset_for_tests()
    yield
    net_ledger._reset_for_tests()


def _identity():
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    return {"device_id": "dev-1", "signing_private": base64.b64encode(raw).decode()}


def test_get_unsigned_without_sync(monkeypatch):
    monkeypatch.setattr(vault_bridge, "load_sync_state", lambda session: None)
    net_ledger.record(net_ledger.UPDATE_CHECK, "updates.example.invalid", "ok")
    net_ledger.record(net_ledger.WEBSITE_ICON, "mybank.example", "ok")
    page = PrivacyProofService(_Controller(), None, None).get()
    doc = page["document"]
    privacy_proof.check_shape(doc)
    assert page["signed"] is False and page["fingerprint"] is None and doc["signature"] is None
    assert privacy_proof.verify_document(doc)["result"] == privacy_proof.UNSIGNED
    assert doc["facts"]["sync"] == "off" and doc["facts"]["items"] == 3
    assert [c["id"] for c in page["claims"]] == ["connections_listed", "no_item_content_sent"]
    assert all(c["text"] for c in page["claims"])
    assert "mybank.example" not in json.dumps(doc) and "secret site" not in json.dumps(doc)
    assert doc["network"]["counts"].get("website_icon") == 1
    assert doc["network"]["entries"][0]["host"] == "updates.example.invalid"
    assert page["since"] == doc["network"]["since"]


def test_get_signed_with_sync_identity(monkeypatch):
    state = SimpleNamespace(device_identity=_identity(), folder_path="C:/sync", lan_peers=(),
                            members=("dev-1", "dev-2"))
    monkeypatch.setattr(vault_bridge, "load_sync_state", lambda session: state)
    page = PrivacyProofService(_Controller(), None, None).get()
    doc = page["document"]
    privacy_proof.check_shape(doc)
    result = privacy_proof.verify_document(doc)
    assert result["result"] == privacy_proof.VALID and result["device_id"] == "dev-1"
    assert page["signed"] is True and page["fingerprint"] == result["fingerprint"]
    assert doc["facts"]["sync"] == "folder" and doc["facts"]["devices"] == 1


def test_a_removed_wifi_peer_is_not_counted_as_a_device(monkeypatch):
    """A removed Wi-Fi peer stays listed with ``revoked`` (its id stays reserved); it is not a device."""
    state = SimpleNamespace(device_identity=_identity(), folder_path=None, members=(),
                            lan_peers=({"device_id": "dev-2", "revoked": False},
                                       {"device_id": "dev-3", "revoked": True}))
    monkeypatch.setattr(vault_bridge, "load_sync_state", lambda session: state)
    facts = PrivacyProofService(_Controller(), None, None).get()["document"]["facts"]
    assert facts["sync"] == "wifi" and facts["devices"] == 1
    state.lan_peers = ({"device_id": "dev-3", "revoked": True},)  # only a removed one left
    facts = PrivacyProofService(_Controller(), None, None).get()["document"]["facts"]
    assert facts["sync"] == "off" and facts["devices"] == 0


def test_locked_refused():
    with pytest.raises(ApiError) as exc:
        PrivacyProofService(_Controller(unlocked=False), None, None).get()
    assert exc.value.code == "locked"


def test_export_writes_file_and_cancel(monkeypatch, tmp_path):
    monkeypatch.setattr(vault_bridge, "load_sync_state", lambda session: None)
    target = tmp_path / "proof.json"
    dialogs = _Dialogs(str(target))
    out = PrivacyProofService(_Controller(), None, dialogs).export()
    assert dialogs.asked.startswith("LocalGateKeys-privacy-proof-") and dialogs.asked.endswith(".json")
    assert out["path"] == str(target) and out["file_name"] == "proof.json" and out["signed"] is False
    assert privacy_proof.verify_bytes(target.read_bytes())["result"] == privacy_proof.UNSIGNED
    with pytest.raises(ApiError) as exc:
        PrivacyProofService(_Controller(), None, _Dialogs(None)).export()
    assert exc.value.code == "cancelled"


def test_item_count_leaves_out_travel_hidden_items(monkeypatch):
    """Finding W-L7: a proof made in travel mode must not show that more items exist than are visible."""
    from localvault import travel

    monkeypatch.setattr(vault_bridge, "load_sync_state", lambda session: None)
    controller = _Controller()
    session = controller.session
    session.all_entries = lambda: [{"id": "a", "tags": ["Work"]}, {"id": "b", "tags": []}]
    session.items = SimpleNamespace(list_items=lambda: [{"id": "c", "kind": "note", "tags": ["work"]}])
    payload = {"entries": [{"id": "a", "kind": "web", "tags": ["Work"]}, {"id": "b", "kind": "web", "tags": []}],
               "items": [{"id": "c", "kind": "note", "tags": ["work"]}]}
    session._require_payload = lambda: payload
    session._read_prefs = lambda: {travel.PREF_KEY: {"on": True, "collections": [], "tags": ["work"], "since": 1}}
    assert PrivacyProofService(controller, None, None).get()["document"]["facts"]["items"] == 1
    session._read_prefs = lambda: {}
    assert PrivacyProofService(controller, None, None).get()["document"]["facts"]["items"] == 3
