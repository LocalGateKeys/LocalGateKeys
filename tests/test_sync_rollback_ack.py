"""Task B4 (Windows): rollback warnings on the Sync page, "This was me", auto-acknowledge after an in-app restore."""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.i18n import t
from localvault.app.sync_view import ISSUE_COPY, ROLLBACK_ACTION, ROLLBACK_TITLE, issue_severity, rollback_view, \
    sync_view
from localvault.sync import lan_sync as lan
from localvault.sync import witness
from localvault.sync.runner import SyncIssue
from localvault.sync.vault_bridge import (
    acknowledge_vault_rollback,
    forget_peer_generation,
    load_sync_state,
    save_sync_state,
)
from localvault.vault import create_vault

from test_app_sync import env  # noqa: F401 - the SyncWebService fixture

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
INSTALL = "install-a"


class Lease:
    def check(self) -> None:
        pass


@pytest.fixture
def joined(tmp_path):
    session = create_vault(tmp_path / "vault.json", "correct horse battery", kdf_overrides=TEST_KDF)
    state = lan.create_lan_group(session, Lease(), install_id=INSTALL)
    return SimpleNamespace(session=session, state=state, path=tmp_path / "vault.json")


def _status(*issues, last_sync=100):
    transport = SimpleNamespace(name="folder", last_sync=last_sync, issues=tuple(issues))
    return SimpleNamespace(transports=(transport,), issues=tuple(issues), running=False, skipped=(), conflicts=0,
                           items_changed=0, license_adopted=False)


# ------------------------------------------------------------------ core (vault_bridge)
def test_acknowledge_clears_the_sticky_flag_and_raises_the_floor_above_witnesses(joined):
    s = joined.session
    witnessed = s.generation + 40
    save_sync_state(s, dataclasses.replace(load_sync_state(s), rollback_suspected=witnessed))
    assert acknowledge_vault_rollback(s, Lease()) is True
    assert load_sync_state(s).rollback_suspected == 0
    assert s.generation > witnessed  # the acknowledging save itself published above every witness
    # The next check with the same witness reports nothing any more.
    own = load_sync_state(s).device_id
    res = witness.check(own, s.generation, [witness.Observation("peer-1", 5, {own: witnessed})], {}, 0)
    assert res.issues == () and res.rollback_suspected == 0
    assert acknowledge_vault_rollback(s, Lease()) is False  # nothing left to acknowledge


def test_dismissing_a_peer_forgets_its_generation_so_it_is_not_reported_again(joined):
    s = joined.session
    save_sync_state(s, dataclasses.replace(load_sync_state(s), peer_generations={"peer-1": 90, "peer-2": 7}))
    assert forget_peer_generation(s, Lease(), "peer-1") is True
    state = load_sync_state(s)
    assert dict(state.peer_generations) == {"peer-2": 7}
    res = witness.check(state.device_id, s.generation, [witness.Observation("peer-1", 30, {})],
                        state.peer_generations, 0)
    assert res.issues == () and res.peer_generations["peer-1"] == 30
    assert forget_peer_generation(s, Lease(), "peer-1") is False


# ------------------------------------------------------------------ view model
def test_rollback_copy_and_severity():
    assert issue_severity("vault-rollback") == "error"
    assert issue_severity("peer-vault-rollback") == "notice"
    view = rollback_view(_status(SyncIssue("vault-rollback", ""), SyncIssue("peer-vault-rollback", "peer-1")), None)
    assert view["own"]["title"] == t(ROLLBACK_TITLE) and view["own"]["action"] == t(ROLLBACK_ACTION)
    assert view["own"]["text"] == t(ISSUE_COPY["vault-rollback"])
    assert view["peers"][0]["id"] == "peer-1" and view["peers"][0]["action"] == "Dismiss"
    assert "older copy of its vault" in view["peers"][0]["text"]
    hidden = rollback_view(_status(SyncIssue("vault-rollback", "")), None, hidden={("vault-rollback", "")})
    assert hidden == {"own": None, "peers": []}


def test_rollback_issues_stay_out_of_the_cards():
    screen = sync_view(_status(SyncIssue("vault-rollback", "")), None, lan_endpoint="", now=200)
    assert screen.folder.issues == () and screen.banner is None


# ------------------------------------------------------------------ web service
def test_acknowledge_needs_confirmation_and_reauth_then_hides_the_warning(env):  # noqa: F811
    env.service._status_changed(env.fake, _status(SyncIssue("vault-rollback", "")))
    assert env.service.view()["rollback"]["own"] is not None
    env.port.answers = [False]
    with pytest.raises(ApiError) as cancelled:
        env.service.acknowledge_rollback()
    assert cancelled.value.code == "cancelled" and env.fake.jobs == []
    env.port.answers = [True]
    env.port.passwords = ["wrong password!"]
    with pytest.raises(ApiError):
        env.service.acknowledge_rollback()
    assert env.fake.jobs == []
    env.port.answers = [True]
    result = env.service.acknowledge_rollback()
    assert result["message"] == t(ISSUE_COPY["rollback-acknowledged"])
    assert env.port.prompts  # the master password was asked
    assert result["rollback"]["own"] is None
    # The same (old) status published again does not bring the warning back; a newer run that reports it does.
    env.service._status_changed(env.fake, _status(SyncIssue("vault-rollback", "")))
    assert env.service.view()["rollback"]["own"] is None
    env.service._status_changed(env.fake, _status(SyncIssue("vault-rollback", ""), last_sync=300))
    assert env.service.view()["rollback"]["own"] is not None


def test_peer_warning_dismiss(env):  # noqa: F811
    env.service._status_changed(env.fake, _status(SyncIssue("peer-vault-rollback", "peer-1")))
    assert [p["id"] for p in env.service.view()["rollback"]["peers"]] == ["peer-1"]
    with pytest.raises(ApiError):
        env.service.dismiss_peer_rollback("peer-2")
    result = env.service.dismiss_peer_rollback("peer-1")
    assert result["rollback"]["peers"] == [] and len(env.fake.jobs) >= 1


def test_a_marker_file_beside_the_vault_never_acknowledges(env):  # noqa: F811
    # A plain file is as easy to plant as an old vault copy, so nothing acknowledges on its own:
    # only "This was me", after the confirmation and re-authentication.
    path = env.controller.session.path
    path.with_name(path.name + ".sync-restored").write_text('{"restored_at": 1}', encoding="utf-8")
    env.service._status_changed(env.fake, _status(SyncIssue("vault-rollback", "")))
    assert env.fake.jobs == [] and env.service.view()["rollback"]["own"] is not None

def test_peers_stop_reporting_after_the_acknowledgement(joined):
    """The floor puts this vault above what the peer remembered, so the peer's own check is silent."""
    s = joined.session
    own = load_sync_state(s).device_id
    peer_remembers = s.generation + 25  # the peer saw this vault at a newer generation before the restore
    save_sync_state(s, dataclasses.replace(load_sync_state(s), rollback_suspected=peer_remembers))
    acknowledge_vault_rollback(s, Lease())
    at_peer = witness.check("peer-1", 3, [witness.Observation(own, s.generation, {})], {own: peer_remembers}, 0)
    assert at_peer.issues == () and at_peer.peer_generations[own] == s.generation


def test_forged_huge_witness_is_implausible_not_a_sticky_rollback():
    res = witness.check("me", 100, [witness.Observation("peer-1", 5, {"me": 2**53 - 1})], {}, 0)
    assert [(i.kind, i.detail) for i in res.issues] == [("witness-implausible", "peer-1")]
    assert res.rollback_suspected == 0
    near = witness.check("me", 100, [witness.Observation("peer-1", 5, {"me": 100 + witness.MAX_WITNESS_JUMP})], {}, 0)
    assert [i.kind for i in near.issues] == ["vault-rollback"]
    assert issue_severity("witness-implausible") == "notice"


def test_acknowledge_clears_even_a_huge_stored_suspicion(joined):
    s = joined.session
    save_sync_state(s, dataclasses.replace(load_sync_state(s), rollback_suspected=2**53 - 1))
    assert acknowledge_vault_rollback(s, Lease()) is True
    assert load_sync_state(s).rollback_suspected == 0
