"""Sync screen view model (``sync_ui``): pure functions only, no Tk windows."""
from __future__ import annotations

import pytest

from localvault.app import sync_view as ui
from localvault.sync.runner import SyncIssue
from localvault.sync.service import SyncStatusView, TransportStatus

NOW = 1_800_000_000
DAY = 86400

#: Every issue kind the folder, LAN, runner and service layers can report.
ALL_KINDS = (
    # required by the task
    "keyring-restored", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
    "stale-self", "stale-device", "member-dropped", "ignored-file", "corrupt", "rollback", "suspicious-rewrite",
    "epoch-behind", "offer-used-or-expired", "too-many-peers", "counter-resynced",
    "trash-full", "history-quota", "bad-peer-data", "busy", "write-failed",
    # the rest of what the layers emit
    "apply-failed", "bad-reply", "device-mismatch", "epoch-mismatch", "error", "folder-missing",
    "folder-unreadable", "group-mismatch", "identity-mismatch", "keyring-corrupt", "keyring-missing",
    "keyring-unreadable", "lan-not-listening", "listen-failed", "local-data", "no-endpoint", "not-joined",
    "peer-epoch-behind", "peer-mismatch", "peer-not-joined", "peer-refused", "peer-rejoin-required",
    "peer-revoked", "state-corrupt", "tampered", "too-large", "unknown-peer", "unreachable", "unreadable",
    "unsafe-member", "bad-chunk", "bad-message", "refused", "bad-offer", "already-joined", "update-needed",
    "bad-name",
    # extended audit 2026-10-24 (M-6 counters, M-7 signed views)
    "implausible-vv", "implausible-counter", "counter-exhausted", "own-file-rewritten", "view-unsigned",
    "view-forged",
)


def _status(*, folder=(), lan=(), global_issues=(), folder_on=True, lan_on=False, last_sync=None,
            running=False, skipped=(), conflicts=0, listening=False) -> SyncStatusView:
    transports = (
        TransportStatus("folder", folder_on, last_sync, last_sync, tuple(folder)),
        TransportStatus("lan", lan_on, last_sync, last_sync, tuple(lan)),
    )
    issues = (*global_issues, *folder, *lan)
    return SyncStatusView(configured=folder_on or lan_on, last_sync=last_sync, transports=transports,
                          issues=tuple(issues), skipped=tuple(skipped), conflicts=conflicts,
                          running=running, listening=listening)


def _member(device_id, name, *, written=NOW, is_self=False):
    return ui.MemberSnapshot(device_id, name, is_self=is_self, file_written_at=written)


def _group(*, folder="C:/Cloud", members=None, peers=(), install_ok=True, own="dev-self",
           item_names=None) -> ui.GroupSnapshot:
    if members is None:
        members = (_member(own, "This PC", is_self=True), _member("dev-b", "Laptop"))
    return ui.GroupSnapshot(device_id=own, folder_path=folder, epoch=2, install_ok=install_ok,
                            members=tuple(members), lan_peers=tuple(peers), item_names=item_names or {})


# --- issue copy --------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_every_issue_kind_has_user_copy(kind):
    assert kind in ui.ISSUE_COPY
    text = ui.issue_text(SyncIssue(kind, "detail"))
    assert text and ("-" not in kind or kind not in text)  # plain words, never the raw code
    assert ui.issue_severity(kind) in ("error", "warning", "notice")


def test_update_needed_copy_is_exact():
    assert ui.issue_text(SyncIssue("update-needed", "dev-b:item-1")) == (
        "One item needs a newer LocalGateKeys on this PC. Update LocalGateKeys; that item waits until then.")
    assert ui.issue_severity("update-needed") == "warning"


def test_unknown_kind_still_gets_generic_copy():
    text = ui.issue_text(SyncIssue("brand-new-kind", "x"))
    assert "brand-new-kind" not in text and text


def test_issue_copy_names_the_file_or_device():
    assert "abc.lgksync" in ui.issue_text(SyncIssue("corrupt", "abc.lgksync: bad-magic"))
    assert "abc.lgksync" in ui.issue_text(SyncIssue("rollback", "abc.lgksync: counter 3 < 5"))
    assert "Laptop" in ui.issue_text(SyncIssue("member-dropped", "dev-b"), names={"dev-b": "Laptop"})
    assert "this pc" in ui.issue_text(SyncIssue("member-dropped", "dev-self"), own_id="dev-self").lower()


def test_password_reuse_warning_copy_is_exact():
    assert ui.PASSWORD_ADVICE == "Write this password down. Never reuse an earlier sync password."


def test_leave_copy_tells_the_others_to_remove_this_device():
    assert "remove this" in ui.LEAVE_TEXT.lower()


def test_stop_kinds_offer_reset():
    for kind in ("folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt",
                 "keyring-corrupt", "tampered"):
        assert kind in ui.RESET_KINDS
    assert "busy" not in ui.RESET_KINDS


# --- dedupe ------------------------------------------------------------------------------------------


def test_each_kind_and_detail_shown_once():
    issue = SyncIssue("corrupt", "x.lgksync: bad")
    status = _status(folder=(issue, issue, SyncIssue("corrupt", "y.lgksync: bad")),
                     global_issues=(issue,))
    view = ui.sync_view(status, _group(), lan_endpoint="", now=NOW)
    texts = [i.text for i in view.folder.issues]
    assert len(texts) == 2 and len(set(texts)) == 2


def test_skipped_records_named_once_with_item_name():
    status = _status(skipped=(("item-1", "bad-id"), ("item-1", "bad-id"), ("item-1", "other"),
                              ("item-2", "bad-id")))
    view = ui.sync_view(status, _group(item_names={"item-1": "Bank\u202e login"}), lan_endpoint="", now=NOW)
    assert len(view.skipped) == 2
    assert "Bank login" in view.skipped[0] and "\u202e" not in view.skipped[0]
    assert view.skipped[1].startswith("1 other item could not be synced")


def test_banner_is_the_most_important_issue():
    status = _status(folder=(SyncIssue("busy"), SyncIssue("corrupt", "x: y"),
                             SyncIssue("rotation-conflict", "z")))
    view = ui.sync_view(status, _group(), lan_endpoint="", now=NOW)
    assert view.folder.banner.kind == "rotation-conflict" and view.folder.banner.reset_offered
    quiet = ui.sync_view(_status(folder=(SyncIssue("busy"),)), _group(), lan_endpoint="", now=NOW)
    assert quiet.folder.banner.kind == "busy" and not quiet.folder.banner.reset_offered


# --- names -------------------------------------------------------------------------------------------


def test_sanitize_strips_controls_and_bidi_and_caps_length():
    assert ui.sanitize_name("Lap\x00top\r\n\x1b[31m") == "Laptop [31m"
    assert ui.sanitize_name("evil\u202etxt.exe") == "eviltxt.exe"
    assert ui.sanitize_name("  a   b  ") == "a b"
    long = ui.sanitize_name("x" * 200)
    assert len(long) == ui.NAME_LIMIT and long.endswith("\u2026")
    assert ui.sanitize_name("") == "Unnamed device"
    assert ui.sanitize_name(None) == "Unnamed device"


def test_member_names_are_sanitised_in_the_view():
    group = _group(members=(_member("dev-self", "Me", is_self=True), _member("dev-b", "Bad\u0007\u200fName")))
    view = ui.sync_view(_status(), group, lan_endpoint="", now=NOW)
    names = [m.name for m in view.folder.members]
    assert "BadName" in names and all(ch.isprintable() for n in names for ch in n)
    assert any(m.is_self for m in view.folder.members)


def test_default_pc_name_is_generic():
    from localvault.sync.keyring import DEFAULT_DEVICE_NAME_PC

    assert ui.default_device_name() == DEFAULT_DEVICE_NAME_PC == "Windows PC"


def test_unnamed_and_hostile_member_names_display_safely():
    group = _group(members=(_member("dev-self", "Me", is_self=True), _member("dev-b", "Unnamed device"),
                            _member("dev-c", "Ev\u202eil\u2066\u0085\u009b")))
    view = ui.sync_view(_status(), group, lan_endpoint="", now=NOW)
    names = sorted(m.name for m in view.folder.members)
    assert "Unnamed device" in names and "Evil" in names
    text = ui.issue_text(SyncIssue("bad-name", "dev-b"), names={"dev-b": "Unnamed device"})
    assert "name" in text and "!" not in text


# --- enabled actions ---------------------------------------------------------------------------------


def test_not_joined_offers_create_and_join():
    view = ui.sync_view(_status(folder_on=False), None, lan_endpoint="", now=NOW)
    assert view.folder.actions == frozenset({"create-group", "join-folder"})
    assert view.wifi.actions == frozenset({"wifi-enable", "join-qr"})


def test_joined_folder_actions():
    view = ui.sync_view(_status(), _group(), lan_endpoint="", now=NOW)
    assert view.folder.actions == frozenset({"sync-now", "change-password", "remove-device", "leave"})
    assert view.folder.state == "on"


def test_unused_members_offered_only_when_there_are_orphans():
    alone = _group(members=(_member("dev-self", "Me", is_self=True),))
    healthy = _group(members=(_member("dev-self", "Me", is_self=True), _member("dev-b", "Fresh", written=NOW - DAY)))
    for group in (alone, healthy):
        assert "show-orphans" not in ui.sync_view(_status(), group, lan_endpoint="", now=NOW).folder.actions
    orphaned = _group(members=(_member("dev-self", "Me", is_self=True), _member("dev-c", "Gone", written=None)))
    assert "show-orphans" in ui.sync_view(_status(), orphaned, lan_endpoint="", now=NOW).folder.actions


def test_sync_now_disabled_while_running():
    view = ui.sync_view(_status(running=True), _group(), lan_endpoint="", now=NOW)
    assert "sync-now" not in view.folder.actions
    assert "running" in view.folder.state_text.lower() or "syncing" in view.folder.state_text.lower()


@pytest.mark.parametrize("kind", ["rotation-conflict", "removed-or-conflict", "rejoin-required"])
def test_conflict_stop_offers_rejoin_and_reset(kind):
    view = ui.sync_view(_status(folder=(SyncIssue(kind, "x"),)), _group(), lan_endpoint="", now=NOW)
    assert {"join-folder", "leave", "reset"} <= view.folder.actions
    assert "change-password" not in view.folder.actions and "remove-device" not in view.folder.actions


def test_other_group_offers_leave_and_reset_not_join():
    view = ui.sync_view(_status(folder=(SyncIssue("folder-has-other-group"),)), _group(), lan_endpoint="",
                        now=NOW)
    assert {"leave", "reset"} <= view.folder.actions
    assert "join-folder" not in view.folder.actions and "change-password" not in view.folder.actions


def test_install_mismatch_blocks_everything_but_rejoin_leave_reset():
    status = _status(global_issues=(SyncIssue("rejoin-required", "install-mismatch"),))
    view = ui.sync_view(status, _group(install_ok=False), lan_endpoint="192.168.1.5:47821", now=NOW)
    assert view.folder.actions == frozenset({"join-folder", "leave", "reset"})
    assert "show-qr" not in view.wifi.actions and "sync-now" not in view.wifi.actions
    assert view.banner is not None and view.banner.kind == "rejoin-required"


def test_state_corrupt_offers_reset_only():
    status = _status(global_issues=(SyncIssue("state-corrupt", "bad"),), folder_on=False)
    view = ui.sync_view(status, None, lan_endpoint="", now=NOW, state_corrupt=True)
    assert view.folder.actions == frozenset({"reset"}) and view.banner.reset_offered


def test_wifi_only_group_offers_add_and_use_folder():
    group = _group(folder=None, members=(), peers=(ui.PeerSnapshot("dev-p", "192.168.1.9:47821"),))
    view = ui.sync_view(_status(folder_on=False, lan_on=True), group, lan_endpoint="192.168.1.5:47821", now=NOW)
    assert view.folder.state == "lan-only"
    assert view.folder.actions == frozenset({"add-folder", "use-folder"}) and view.folder.hint
    assert "leave" not in view.folder.hint.lower()
    assert ui._ACTION_LABELS["add-folder"] == "Add a cloud folder to this group…"
    assert ui._ACTION_LABELS["use-folder"] == "Use this group's cloud folder…"
    assert {"show-qr", "sync-now", "remove-device", "leave", "wifi-disable"} <= view.wifi.actions
    assert "join-qr" not in view.wifi.actions
    # never for a folder group, a group-less vault, or a group set up on another PC
    assert not {"add-folder", "use-folder"} & ui.sync_view(_status(), _group(), lan_endpoint="", now=NOW).folder.actions
    assert not {"add-folder", "use-folder"} & ui.sync_view(_status(), None, lan_endpoint="", now=NOW).folder.actions
    moved = _group(folder=None, members=(), install_ok=False)
    assert not {"add-folder", "use-folder"} & ui.sync_view(_status(), moved, lan_endpoint="", now=NOW).folder.actions


def test_folder_setup_dialogs():
    add = ui.folder_setup("add-folder")
    use = ui.folder_setup("use-folder")
    assert add.confirm_twice and not use.confirm_twice  # a new password twice; the folder's password once
    assert add.title and add.intro and add.busy and add.done_text
    assert use.title and use.intro and use.busy and use.done_text
    assert "!" not in add.intro + use.intro + add.done_text + use.done_text
    assert ui.folder_setup("create-group") is None
    for reason in ("already-has-folder", "folder-has-other-group", "different-group-key", "epoch-mismatch",
                   "already-member", "keyring-changed", "password"):
        text = ui.error_text(type("E", (Exception,), {"reason": reason})())
        assert text and "details are in the error log" not in text.lower()
        assert "-" not in reason or reason not in text  # plain words, never the raw code


def test_wifi_off_and_ready_states():
    off = ui.sync_view(_status(), _group(), lan_endpoint="", now=NOW)
    assert off.wifi.actions == frozenset({"wifi-enable"}) and off.wifi.state == "off"
    ready = ui.sync_view(_status(folder_on=False), None, lan_endpoint="192.168.1.5:47821", now=NOW)
    assert ready.wifi.actions == frozenset({"show-qr", "join-qr", "wifi-disable"})


def test_wifi_remove_needs_a_peer():
    on = ui.sync_view(_status(lan_on=True), _group(), lan_endpoint="192.168.1.5:47821", now=NOW)
    assert "remove-device" not in on.wifi.actions and "show-qr" in on.wifi.actions
    group = _group(peers=(ui.PeerSnapshot("dev-p", None),))
    with_peer = ui.sync_view(_status(lan_on=True), group, lan_endpoint="192.168.1.5:47821", now=NOW)
    assert "remove-device" in with_peer.wifi.actions
    assert with_peer.wifi.members[0].detail  # "connects to this PC"


def test_unavailable_service_disables_everything():
    view = ui.sync_view(None, None, lan_endpoint="", now=NOW, available=False)
    assert view.folder.actions == frozenset() and view.wifi.actions == frozenset()
    assert view.folder.state_text


def test_last_sync_and_conflicts_text():
    view = ui.sync_view(_status(last_sync=NOW - 120, conflicts=3), _group(), lan_endpoint="", now=NOW)
    assert view.folder.last_sync_text == "Last synced 2 min ago"
    # one since-unlock counter: shown once, at screen level, not on each card
    assert view.conflicts == 3 and "3" in view.conflicts_text
    assert not hasattr(view.folder, "conflicts_text") and not hasattr(view.wifi, "conflicts_text")
    assert ui.sync_view(_status(), _group(), lan_endpoint="", now=NOW).conflicts_text == ""
    never = ui.sync_view(_status(), _group(), lan_endpoint="", now=NOW)
    assert never.folder.last_sync_text == "Not synced yet"


# --- orphan members ----------------------------------------------------------------------------------


def test_orphans_are_members_without_a_file_or_with_a_stale_one():
    group = _group(members=(
        _member("dev-self", "Me", is_self=True, written=None),
        _member("dev-b", "Fresh", written=NOW - DAY),
        _member("dev-c", "Gone", written=None),
        _member("dev-d", "Old", written=NOW - 400 * DAY),
    ))
    orphans = ui.orphan_members(group, now=NOW)
    assert [(o.device_id, o.orphan) for o in orphans] == [("dev-c", "no-file"), ("dev-d", "stale")]
    assert all(o.removable for o in orphans)


# --- password strength gate --------------------------------------------------------------------------


def test_password_gate_requires_twelve_chars_strong_and_match():
    weak = ui.check_sync_password("password", "password")
    assert not weak.ok and "12" in weak.message
    common = ui.check_sync_password("passwordpassword", "passwordpassword")
    assert not common.ok and common.score < 3
    strong = "correct horse battery staple 7!"
    mismatch = ui.check_sync_password(strong, strong + "x")
    assert not mismatch.ok and "match" in mismatch.message.lower()
    good = ui.check_sync_password(strong, strong)
    assert good.ok and good.score >= 3 and good.label in ("Strong", "Very strong")
    empty = ui.check_sync_password("", "")
    assert not empty.ok


# --- LAN endpoint ------------------------------------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("192.168.1.5:47821", "192.168.1.5:47821"),
    (" 10.0.0.2:5000 ", "10.0.0.2:5000"),
    ("172.16.4.1:47821", "172.16.4.1:47821"),
    ("169.254.10.3:47821", "169.254.10.3:47821"),
    ("[fe80::1]:47821", "[fe80::1]:47821"),
    ("[fd00::5]:47821", "[fd00::5]:47821"),
])
def test_lan_endpoint_accepts_private_and_link_local(text, expected):
    assert ui.validate_lan_endpoint(text) == (expected, "")


@pytest.mark.parametrize("text", [
    "8.8.8.8:47821", "127.0.0.1:47821", "0.0.0.0:47821", "224.0.0.1:47821", "255.255.255.255:47821",
    "192.168.1.5", "192.168.1.5:0", "192.168.1.5:99999", "192.168.1.5:80", "router.local:47821",
    "192.168.1.5:abc", "", "[2001:4860::1]:47821", "fe80::1:47821",
])
def test_lan_endpoint_rejects_public_loopback_and_malformed(text):
    value, error = ui.validate_lan_endpoint(text)
    assert value is None and error


def test_suggested_endpoint_picks_a_private_ipv4_and_the_fixed_port():
    assert ui.suggest_lan_endpoint(["127.0.0.1", "8.8.8.8", "192.168.1.20", "10.0.0.3"]) == \
        f"192.168.1.20:{ui.DEFAULT_LAN_PORT}"
    assert ui.suggest_lan_endpoint(["169.254.3.3"]) == f"169.254.3.3:{ui.DEFAULT_LAN_PORT}"
    assert ui.suggest_lan_endpoint(["127.0.0.1", "not-an-ip"]) is None
    assert ui.validate_lan_endpoint(ui.suggest_lan_endpoint(["10.1.2.3"]))[1] == ""


# --- QR countdown ------------------------------------------------------------------------------------


def test_qr_countdown_text():
    assert ui.countdown_text(120) == "Expires in 2:00"
    assert ui.countdown_text(5.4) == "Expires in 0:06"
    assert ui.countdown_text(0) == "Expired"


# --- action errors -----------------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["password", "password-reused", "weak-password", "folder-in-use", "no-group",
                                    "different-group", "keyring-changed", "folder-error", "folder-missing",
                                    "too-many-members", "cannot-remove-self", "already-joined", "not-joined",
                                    "rejoin-required", "offer-used-or-expired", "unreachable", "too-many-peers",
                                    "bad-offer", "refused"])
def test_action_errors_have_copy(reason):
    from localvault.sync.folder_transport import FolderSyncError
    from localvault.sync.lan_sync import LanSyncError

    for exc in (FolderSyncError(reason, "detail"), LanSyncError(reason, "detail")):
        text = ui.error_text(exc)
        assert text and text != reason and ("-" not in reason or reason not in text)


def test_unexpected_action_error_is_generic():
    assert "error log" in ui.error_text(RuntimeError("boom")).lower()


def test_lan_endpoint_setting_round_trips_and_drops_bad_values(tmp_path):
    import json

    from localvault.settings import AppSettings

    path = tmp_path / "settings.json"
    assert AppSettings().sync_lan_endpoint == ""  # Wi-Fi sync is off by default
    settings = AppSettings(sync_lan_endpoint=" 192.168.1.4:47821 ")
    settings.save(path)
    assert AppSettings.load(path).sync_lan_endpoint == "192.168.1.4:47821"
    raw = json.loads(path.read_text(encoding="utf-8"))
    for bad in ("8.8.8.8:47821", "127.0.0.1:47821", 5, None):
        raw["sync_lan_endpoint"] = bad
        path.write_text(json.dumps(raw), encoding="utf-8")
        assert AppSettings.load(path).sync_lan_endpoint == ""


# --- worker jobs (called directly, no worker thread, no Tk) --------------------------------------------


class _Gate:
    def __init__(self):
        import contextlib

        self.events = []

        @contextlib.contextmanager
        def mark(name):
            self.events.append(f"{name}-in")
            yield
            self.events.append(f"{name}-out")

        self.ui_released = lambda: mark("ui")
        self.released = lambda: mark("released")


def test_snapshot_job_reads_the_stored_group(tmp_path):
    from localvault.sync import lan_sync as lan
    from localvault.vault import create_vault

    session = create_vault(tmp_path / "v.json", "synthetic master",
                           kdf_overrides={"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32})
    lease = lambda: None  # noqa: E731
    assert ui.snapshot_job("install-a")(session, lease, _Gate()) == (None, False)
    state = lan.create_lan_group(session, lease, install_id="install-a")
    snap, corrupt = ui.snapshot_job("install-a")(session, lease, _Gate())
    assert not corrupt and snap.device_id == state.device_id and snap.install_ok and snap.folder_path is None
    other, _ = ui.snapshot_job("install-b")(session, lease, _Gate())
    assert not other.install_ok
    session._require_typed_catalog()["sync_group"] = {"broken": True}
    assert ui.snapshot_job("install-a")(session, lease, _Gate()) == (None, True)


def test_qr_enrollment_round_trip_releases_the_gate():
    gate = _Gate()
    calls = []

    class Inner:
        def enroll(self, *args, **kwargs):
            calls.append(list(gate.events))
            return b"reply"

    assert ui._ReleasingEnroll(Inner(), gate).enroll("endpoint", b"x") == b"reply"
    assert calls == [["released-in"]] and gate.events == ["released-in", "released-out"]


# --- fix round 1 -------------------------------------------------------------------------------------


def test_rotation_copy_lists_qr_paired_devices_that_must_pair_again():
    peers = (ui.PeerSnapshot("dev-p", None), ui.PeerSnapshot("dev-q", "192.168.1.9:47821"))
    group = _group(members=(_member("dev-self", "Me", is_self=True), _member("dev-q", "Office‮PC")),
                   peers=peers)
    text = ui.rotation_intro(group)
    assert "paired by QR" in text and "pair" in text.lower() and "again" in text
    assert "Device dev-p" in text and "OfficePC" in text and "‮" not in text
    removing = ui.rotation_intro(group, removing="dev-p")
    assert "Device dev-p" not in removing.split("paired by QR", 1)[1]  # the removed one is not listed
    plain = ui.rotation_intro(_group())
    assert "QR" not in plain and plain


def test_wifi_first_warning_removed():
    for name in ("wifi_first_needs_confirm", "WIFI_FIRST_TEXT", "WIFI_FIRST_CHOICES"):
        assert not hasattr(ui, name)
    # Show QR on a group-less vault is offered directly (it starts a Wi-Fi group that can add a folder later)
    ready = ui.sync_view(_status(folder_on=False), None, lan_endpoint="192.168.1.5:47821", now=NOW)
    assert "show-qr" in ready.wifi.actions
    assert ui.UNNAMED_DEVICE == "Unnamed device"


def test_lan_device_mismatch_names_the_device_not_a_file():
    lan = ui.issue_text(SyncIssue("device-mismatch", "dev-b: device-mismatch"), names={"dev-b": "Laptop"})
    assert "Laptop" in lan and "file" not in lan.lower()
    folder = ui.issue_text(SyncIssue("device-mismatch", "dev-b.lgksync: device-mismatch"))
    assert "The file dev-b.lgksync" in folder


def test_keyring_rollback_has_its_own_copy_and_stops_the_card():
    issue = SyncIssue("rollback", "rollback: keyring epoch 1 is older than trusted 2")
    text = ui.issue_text(issue)
    assert "key file" in text and "The file" not in text
    view = ui.sync_view(_status(folder=(issue,)), _group(), lan_endpoint="", now=NOW)
    assert view.folder.banner.kind == "keyring-rollback" and view.folder.banner.reset_offered
    assert view.folder.state == "stopped" and "reset" in view.folder.actions
    file_rollback = ui.sync_view(_status(folder=(SyncIssue("rollback", "a.lgksync: counter 1 < 2"),)), _group(),
                                 lan_endpoint="", now=NOW)
    assert file_rollback.folder.banner.kind == "rollback" and file_rollback.folder.state == "on"


def test_epoch_behind_copy_matches_the_offered_leave_action():
    """Wi-Fi-only group: leave, then pair again (Leave offered)."""
    text = ui.issue_text(SyncIssue("epoch-behind", "dev-p"), names={"dev-p": "Phone"})
    assert "Leave" in text and "pair" in text.lower() and "Join the folder" not in text
    endpoint = "192.168.1.5:47821"
    view = ui.sync_view(_status(lan=(SyncIssue("epoch-behind", "dev-p"),), lan_on=True),
                        _group(folder=None, members=()), lan_endpoint=endpoint, now=NOW)
    assert "leave" in view.wifi.actions
    assert any("Leave" in i.text for i in view.wifi.issues)


def test_epoch_behind_in_a_folder_group_says_let_the_folder_sync_and_offers_no_leave():
    """I6: a cloud-folder member gets the new key from the folder (or joins again); never Leave."""
    text = ui.issue_text(SyncIssue("epoch-behind", "dev-p"), names={"dev-p": "Phone"}, folder=True)
    assert "cloud folder" in text and "join the folder again" in text.lower() and "newest sync password" in text
    assert "Leave" not in text and "pair it again" not in text
    view = ui.sync_view(_status(lan=(SyncIssue("epoch-behind", "dev-p"),), lan_on=True), _group(),
                        lan_endpoint="192.168.1.5:47821", now=NOW)
    assert "leave" not in view.wifi.actions
    (issue,) = [i for i in view.wifi.issues if i.kind == "epoch-behind"]
    assert "cloud folder" in issue.text and "Leave" not in issue.text


def test_wifi_only_remove_device_copy_says_remove_it_on_every_paired_pc():
    """M1: Wi-Fi pairing is per PC, so the copy says to remove the device on every PC it is paired with."""
    text = ui.remove_wifi_device_text("Phone")
    assert "Remove Phone from Wi-Fi sync?" in text
    assert "every other PC it is paired with" in text


def test_leave_copy_differs_for_wifi_only_groups():
    folder = ui.leave_text(_group())
    wifi = ui.leave_text(_group(folder=None, members=()))
    assert folder == ui.LEAVE_TEXT and "remove this" in folder.lower()
    assert wifi != folder and "sync folder" not in wifi and "Wi-Fi" in wifi and "pair" in wifi.lower()


def test_reset_result_copy_reports_failures():
    assert "reset" in ui.reset_result_text(True).lower()
    assert "nothing to reset" in ui.reset_result_text(False).lower()
    failed = ui.reset_result_text(None)
    assert "nothing to reset" not in failed.lower() and "could not" in failed.lower()


def test_clipboard_is_cleared_only_if_it_still_holds_the_code():
    assert ui.QR_CLIPBOARD_SECONDS == 120
    assert ui.should_clear_clipboard("lgk-pair:abc", "lgk-pair:abc") is True
    assert ui.should_clear_clipboard("something else", "lgk-pair:abc") is False
    assert ui.should_clear_clipboard(None, "lgk-pair:abc") is False




# --- adding a cloud folder to a Wi-Fi group -----------------------------------------------------------


def test_add_and_use_folder_jobs_release_the_ui_and_do_not_run(tmp_path, monkeypatch):
    from localvault.sync import folder_transport as ft

    calls = []

    def fake(name):
        def call(root, session, lease, password, device_name, **kwargs):
            calls.append((name, root, password, device_name, kwargs))
            return "report"
        return call

    monkeypatch.setattr(ft, "add_folder_to_group", fake("add"))
    monkeypatch.setattr(ft, "attach_folder", fake("attach"))
    gate = _Gate()
    assert ui.add_folder_job("C:/Cloud", "pw", "Windows PC", "install-a")("s", "l", gate) == "report"
    assert ui.attach_folder_job("C:/Cloud", "pw", "Windows PC", "install-a")("s", "l", gate) == "report"
    for (name, root, password, device_name, kwargs), want in zip(calls, ("add", "attach"), strict=True):
        assert (name, root, password, device_name) == (want, "C:/Cloud", "pw", "Windows PC")
        assert kwargs["install_id"] == "install-a" and kwargs["run"] is False
        assert kwargs["ui_released"] is gate.ui_released


