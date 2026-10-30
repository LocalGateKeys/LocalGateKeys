"""Scan sheet: a QR code from a picture, a pasted snip or the webcam, added to new or matching logins."""
from __future__ import annotations

import base64
import json
import logging

import pytest
from test_app_login_extras import KDF, MASTER, Port, Sched

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.qr_accounts import QrAccountsService
from localvault.app.qr_import import QrImportService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.totp import migration_match_score

SECRET_A = b"0123456789"
SECRET_B = b"abcdefghij"
SECRET_C = b"ABCDEFGHIJ"
KEY_URI = "otpauth://totp/Alpha:ann?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"


def _field(number, payload):
    return bytes([(number << 3) | 2, len(payload)]) + payload


def export_uri(accounts, index=0, size=1):
    """A Google Authenticator export link with several accounts and a batch position."""
    blob = b""
    for secret, name, issuer in accounts:
        otp = _field(1, secret) + _field(2, name.encode()) + _field(3, issuer.encode()) + bytes(
            [4 << 3, 1, 5 << 3, 1, 6 << 3, 2])
        blob += _field(1, otp)
    blob += bytes([2 << 3, size, 3 << 3, index])
    return "otpauth-migration://offline?data=" + base64.b64encode(blob).decode()


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class UpgradePort(Port):
    def __init__(self):
        super().__init__()
        self.upgrades = []

    def show_upgrade(self, **kwargs):
        self.upgrades.append(kwargs)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port = UpgradePort()
    editor = LoginEditorService(controller, port, generate=lambda: "Generated-Pass-123!")
    extras = LoginExtrasService(controller, port, editor)
    accounts = QrAccountsService(controller, editor, port, generate=lambda: "Generated-Pass-123!")
    session = controller.session
    alpha = session.create_web_login(urls=[{"url": "https://alpha.test", "match": "exact_origin"}], username="ann",
                                     password="alpha-pass-1", label="Alpha")
    return accounts, controller, port, editor, alpha, extras, bus


def entry(controller, entry_id):
    return controller.session.get_entry(entry_id)


def test_match_score_is_the_migration_matcher():
    account = {"issuer": "Alpha", "label": "ann@alpha.test"}
    assert migration_match_score(account, "Alpha", "https://alpha.test") > 0
    assert migration_match_score(account, "Beta", "https://beta.test") == 0


def test_single_key_lists_matching_logins_without_secrets(env):
    accounts, _controller, _port, _editor, alpha, _extras, _bus = env
    view = accounts.collect([KEY_URI])
    assert view["kind"] == "key" and view["complete"] is True
    row = view["accounts"][0]
    assert row["issuer"] == "Alpha" and row["label"] == "ann"
    assert [m["id"] for m in row["matches"]] == [alpha]
    assert "JBSWY3DP" not in json.dumps(view)


def test_single_key_opens_the_matching_login_with_the_key_applied(env):
    accounts, controller, _port, editor, alpha, _extras, _bus = env
    view = accounts.collect([KEY_URI])
    draft = accounts.open(view["token"], 0, alpha)
    assert draft["is_new"] is False and draft["totp_configured"] is True and draft["dirty"] is True
    assert editor._drafts[draft["draft_id"]].draft.totp_text.startswith("otpauth://totp/")
    assert not entry(controller, alpha).get("totp")  # nothing saved until the person saves
    with pytest.raises(ApiError):
        accounts.open(view["token"], 0, alpha)  # a single key is used once


def test_single_key_without_a_match_opens_a_prefilled_new_login(env):
    accounts, _controller, _port, editor, _alpha, _extras, _bus = env
    view = accounts.collect(["otpauth://totp/Gamma:gail@gamma.test?secret=JBSWY3DPEHPK3PXP&issuer=Gamma"])
    assert view["accounts"][0]["matches"] == []
    draft = accounts.open(view["token"], 0, None)
    assert draft["is_new"] is True and draft["label"] == "Gamma" and draft["username"] == "gail@gamma.test"
    assert draft["totp_configured"] is True


def test_export_adds_selected_accounts_in_one_go(env):
    accounts, controller, _port, _editor, alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_A, "ann", "Alpha"), (SECRET_B, "bob", "Beta"),
                                         (SECRET_C, "cat", "Gamma")])])
    assert view["kind"] == "export" and [a["issuer"] for a in view["accounts"]] == ["Alpha", "Beta", "Gamma"]
    assert view["accounts"][0]["best"] == alpha
    assert "secret" not in json.dumps(view)
    result = accounts.add(view["token"], [
        {"index": 0, "target": alpha},
        {"index": 1, "target": "new", "website": "beta.test"},
    ])
    assert result["added"] == 1 and result["updated"] == 1 and result["skipped"] == []
    assert entry(controller, alpha)["totp"]["secret"]
    assert entry(controller, alpha)["password"] == "alpha-pass-1"  # only the key changes
    beta = [e for e in controller.session.all_entries() if e.get("username") == "bob"]
    assert len(beta) == 1 and beta[0]["label"] == "Beta" and beta[0]["totp"]["secret"]
    assert len(controller.session.all_entries()) == 2  # Gamma was not selected
    with pytest.raises(ApiError):
        accounts.add(view["token"], [{"index": 2, "target": "new", "website": "gamma.test"}])  # token used up


def test_duplicates_are_skipped_not_doubled(env):
    accounts, controller, _port, _editor, alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_A, "ann", "Alpha"), (SECRET_B, "ann", "Alpha2")])])
    result = accounts.add(view["token"], [
        {"index": 0, "target": "new", "website": "https://alpha.test"},  # alpha.test + ann already exists
        {"index": 1, "target": alpha},
    ])
    assert result["updated"] == 1 and result["added"] == 0
    assert [s["issuer"] for s in result["skipped"]] == ["Alpha"]
    assert "already" in result["skipped"][0]["reason"]
    assert len(controller.session.all_entries()) == 1
    again = accounts.collect([export_uri([(SECRET_B, "ann", "Alpha2")])])
    assert again["accounts"][0]["already"] == "Alpha"  # the key is already in that login


def test_same_account_twice_in_one_add_is_refused(env):
    accounts, _controller, _port, _editor, alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_A, "ann", "Alpha")])])
    with pytest.raises(ApiError) as twice:
        accounts.add(view["token"], [{"index": 0, "target": alpha}, {"index": 0, "target": "new", "website": "a.test"}])
    assert twice.value.code == "invalid"


def test_new_login_needs_a_website(env):
    accounts, controller, _port, _editor, _alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    with pytest.raises(ApiError) as missing:
        accounts.add(view["token"], [{"index": 0, "target": "new", "website": ""}])
    assert missing.value.code == "invalid" and "Beta" in missing.value.message
    assert len(controller.session.all_entries()) == 1
    # The list is kept so the person can fix the website and try again.
    assert accounts.add(view["token"], [{"index": 0, "target": "new", "website": "beta.test"}])["added"] == 1


def test_free_plan_shows_the_upgrade_screen_and_writes_nothing(env):
    accounts, controller, port, _editor, alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_A, "ann", "Alpha")])])
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as pro:
        accounts.collect([KEY_URI])
    assert pro.value.code == "pro_required" and port.upgrades
    with pytest.raises(ApiError) as add:
        accounts.add(view["token"], [{"index": 0, "target": alpha}])
    assert add.value.code == "pro_required"
    assert not entry(controller, alpha).get("totp")


def test_item_limit_shows_the_upgrade_screen(env):
    accounts, controller, port, _editor, _alpha, _extras, _bus = env
    controller.session.item_limit = 1  # Alpha already uses the only slot
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    with pytest.raises(ApiError) as limit:
        accounts.add(view["token"], [{"index": 0, "target": "new", "website": "beta.test"}])
    assert limit.value.code == "item_limit" and port.upgrades
    assert len(controller.session.all_entries()) == 1


def test_multi_part_export_asks_for_the_next_code_and_merges(env):
    accounts, controller, _port, _editor, _alpha, _extras, _bus = env
    first = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")], index=0, size=2)])
    assert first["complete"] is False and first["batch"] == {"size": 2, "scanned": [0], "missing": [1]}
    again = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")], index=0, size=2)], first["token"])
    assert len(again["accounts"]) == 1  # the same code twice adds nothing
    with pytest.raises(ApiError) as other:
        accounts.collect([export_uri([(SECRET_C, "cat", "Gamma")], index=1, size=3)], first["token"])
    assert other.value.code == "invalid"  # a code from a different export
    with pytest.raises(ApiError):
        accounts.collect([KEY_URI], first["token"])  # a single key is not part of an export
    second = accounts.collect([export_uri([(SECRET_C, "cat", "Gamma")], index=1, size=2)], first["token"])
    assert second["complete"] is True and [a["issuer"] for a in second["accounts"]] == ["Beta", "Gamma"]
    result = accounts.add(second["token"], [{"index": 0, "target": "new", "website": "beta.test"},
                                            {"index": 1, "target": "new", "website": "gamma.test"}])
    assert result["added"] == 2 and len(controller.session.all_entries()) == 3


def test_lock_forgets_scanned_accounts(env):
    accounts, controller, _port, _editor, _alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    controller.lock()
    assert accounts._scans == {}
    with pytest.raises(ApiError):
        accounts.add(view["token"], [{"index": 0, "target": "new", "website": "beta.test"}])


def test_discard_and_bad_choices(env):
    accounts, _controller, _port, _editor, _alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    for bad in ([], [{"index": 5, "target": "new", "website": "b.test"}], [{"index": 0, "target": "no-such-id"}],
                ["x"]):
        with pytest.raises(ApiError) as invalid:
            accounts.add(view["token"], bad)
        assert invalid.value.code == "invalid"
    accounts.discard(view["token"])
    assert accounts._scans == {}


def test_secrets_never_reach_logs_or_errors(env, caplog):
    accounts, _controller, _port, _editor, _alpha, _extras, _bus = env
    caplog.set_level(logging.DEBUG)
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    with pytest.raises(ApiError) as bad:
        accounts.add(view["token"], [{"index": 0, "target": "new", "website": "not a website"}])
    secret = base64.b32encode(SECRET_B).decode().rstrip("=")
    assert secret not in bad.value.message and secret not in caplog.text


# ------------------------------------------------------- scanning without an open editor
cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")


def qr_image(text, size=900):
    code = cv2.QRCodeEncoder.create().encode(text)
    code = cv2.resize(code, (400, 400), interpolation=cv2.INTER_NEAREST)
    screen = np.full((size, size * 16 // 9), 255, dtype=np.uint8)
    screen[200:600, 300:700] = code
    return cv2.cvtColor(screen, cv2.COLOR_GRAY2BGR)


def as_data_url(image, ext=".png", mime="image/png"):
    ok, data = cv2.imencode(ext, image)
    assert ok
    return f"data:{mime};base64," + base64.b64encode(data.tobytes()).decode("ascii")


def scanner(env, frames=()):
    accounts, controller, _port, editor, _alpha, extras, bus = env
    feed = list(frames)

    class Capture:
        def read(self):
            return (True, feed.pop(0)) if feed else (True, np.full((720, 1280, 3), 200, dtype=np.uint8))

        def set(self, *_a):
            return True

        def release(self):
            pass

    return QrImportService(controller, editor, extras, emit=bus.emit, accounts=accounts,
                           open_camera=lambda _cv2, index: (Capture(), index), sleep=lambda _s: None)


def test_sheet_reads_a_picture_file_png_jpeg_and_bmp(env):
    qr = scanner(env)
    for ext, mime in ((".png", "image/png"), (".jpg", "image/jpeg"), (".bmp", "image/bmp")):
        view = qr.sheet_scan_image(as_data_url(qr_image(KEY_URI), ext, mime))
        assert view["kind"] == "key" and view["accounts"][0]["issuer"] == "Alpha"


def test_sheet_refuses_a_bad_image_and_releases_the_scanner(env):
    qr = scanner(env)
    for bad in ("hello", "data:text/plain;base64,aGk=", "data:image/gif;base64," + base64.b64encode(b"GIF89a").decode(),
                "data:image/png;base64," + base64.b64encode(b"not a png").decode()):
        with pytest.raises(ApiError) as invalid:
            qr.sheet_scan_image(bad)
        assert invalid.value.code == "invalid"
    with pytest.raises(ApiError) as missing:
        qr.sheet_scan_image(as_data_url(qr_image("https://example.test")))
    assert missing.value.code == "not_found"
    assert qr._busy.acquire(blocking=False)


def test_sheet_scan_on_the_free_plan_shows_the_upgrade_screen_before_decoding(env):
    _accounts, controller, port, *_ = env
    qr = scanner(env)
    controller.session.pro_features = frozenset()
    with pytest.raises(ApiError) as pro:
        qr.sheet_scan_image(as_data_url(qr_image(KEY_URI)))
    assert pro.value.code == "pro_required" and port.upgrades
    assert qr._busy.acquire(blocking=False)


def test_sheet_camera_reads_an_export_and_the_next_part(env):
    first = export_uri([(SECRET_B, "bob", "Beta")], index=0, size=2)
    qr = scanner(env, [qr_image(first)])
    view = qr.sheet_scan_camera()
    assert view["kind"] == "export" and view["complete"] is False
    qr2 = scanner(env, [qr_image(export_uri([(SECRET_C, "cat", "Gamma")], index=1, size=2))])
    assert qr2.sheet_scan_camera(view["token"])["complete"] is True


def test_sheet_scan_needs_an_unlocked_vault(env):
    _accounts, controller, *_ = env
    qr = scanner(env)
    controller.lock()
    with pytest.raises(ApiError) as locked:
        qr.sheet_scan_image(as_data_url(qr_image(KEY_URI)))
    assert locked.value.code == "locked"


def test_bridge_exposes_the_scan_sheet_calls():
    from localvault.api import bridge

    for name in ("qr_sheet_scan_image", "qr_sheet_scan_camera", "qr_sheet_open", "qr_sheet_add", "qr_sheet_discard"):
        assert name in bridge.PAGE_CALLS
    # Scans wait for the camera and take the vault lock themselves; the rest run under it.
    assert {"qr_sheet_scan_image", "qr_sheet_scan_camera"} <= bridge._NO_VAULT_LOCK
    assert not {"qr_sheet_open", "qr_sheet_add", "qr_sheet_discard"} & bridge._NO_VAULT_LOCK


def test_scan_entry_points_in_tools_and_the_palette():
    from localvault.shell.commands import COMMANDS
    from localvault.shell.nav import TOOLS_ENTRIES

    scan = next(e for e in TOOLS_ENTRIES if e.label == "Scan QR code")
    assert scan.action == "scan_qr_clicked"
    command = next(c for c in COMMANDS if c.id == "scan-qr")
    assert command.title == "Scan QR code" and "2fa" in command.keywords


# ----------------------------------------------------------------- fix round 1
def test_best_match_only_when_issuer_and_account_match_exactly(env):
    accounts, controller, _port, _editor, alpha, _extras, _bus = env
    # "Al" is a substring of Alpha: listed as a candidate maybe, never picked by default.
    view = accounts.collect([export_uri([(SECRET_A, "an", "Al"), (SECRET_B, "ANN", "alpha")])])
    assert view["accounts"][0]["best"] is None
    assert view["accounts"][1]["best"] == alpha  # exact, case-insensitive
    controller.session.create_web_login(urls=[{"url": "https://alpha2.test", "match": "exact_origin"}],
                                        username="ann", password="x-pass-2", label="Alpha")
    again = accounts.collect([export_uri([(SECRET_B, "ann", "Alpha")])])
    assert again["accounts"][0]["best"] is None  # two exact candidates: ambiguous


def test_replacing_an_existing_2fa_key_needs_confirmation(env):
    accounts, controller, _port, _editor, alpha, _extras, _bus = env
    first = accounts.collect([export_uri([(SECRET_A, "ann", "Alpha")])])
    accounts.add(first["token"], [{"index": 0, "target": alpha}])
    before = entry(controller, alpha)["totp"]["secret"]
    view = accounts.collect([export_uri([(SECRET_B, "ann", "Alpha")])])
    assert view["accounts"][0]["matches"][0]["has_totp"] is True
    with pytest.raises(ApiError) as confirm:
        accounts.add(view["token"], [{"index": 0, "target": alpha}])
    assert confirm.value.code == "confirm_replace" and "Alpha" in confirm.value.message
    assert entry(controller, alpha)["totp"]["secret"] == before
    assert accounts.add(view["token"], [{"index": 0, "target": alpha, "replace": True}])["updated"] == 1
    assert entry(controller, alpha)["totp"]["secret"] != before


def test_new_logins_are_marked_as_needing_their_real_password(env):
    accounts, controller, _port, _editor, _alpha, _extras, _bus = env
    view = accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])
    result = accounts.add(view["token"], [{"index": 0, "target": "new", "website": "beta.test"}])
    beta = next(e for e in controller.session.all_entries() if e.get("username") == "bob")
    assert "needs-password" in beta["tags"]
    assert beta["notes"] == ("Password not set — added from a 2FA QR code. "
                             "Replace this generated password with your real one.")
    assert "Add to existing login" in result["message"]


def test_health_leaves_out_logins_that_need_their_real_password():
    from localvault.password_tools import vault_health

    entries = [
        {"id": "a", "password": "", "tags": ["needs-password"], "totp": {"secret": "X"}},
        {"id": "b", "password": "same-pass", "tags": ["needs-password"], "totp": {"secret": "X"}},
        {"id": "c", "password": "same-pass", "tags": [], "totp": {"secret": "X"}},
    ]
    report = vault_health(entries)
    assert "a" not in report["weak_ids"] and "b" not in report["reused_ids"] and "c" not in report["reused_ids"]


def test_at_most_two_live_scans(env):
    accounts, *_ = env
    tokens = [accounts.collect([export_uri([(SECRET_B, "bob", "Beta")])])["token"] for _ in range(3)]
    assert list(accounts._scans) == tokens[1:]


def test_at_most_256_accounts_per_scan_across_parts(env):
    accounts, *_ = env
    import localvault.totp as totp

    def part(i, n):
        return export_uri([(bytes([i % 250 + 1, n % 250 + 1]) * 5, f"u{n}", f"I{n}") for n in range(i * 100, i * 100 + 100)],
                          index=i, size=3)

    original = totp.MAX_MIGRATION_ACCOUNTS
    totp.MAX_MIGRATION_ACCOUNTS = max(original, 100)
    try:
        view = accounts.collect([part(0, 0)])
        view = accounts.collect([part(1, 0)], view["token"])
        assert len(view["accounts"]) == 200
        with pytest.raises(ApiError) as many:
            accounts.collect([part(2, 0)], view["token"])
        assert many.value.code == "invalid" and "256" in many.value.message
        assert len(accounts.view(view["token"])["accounts"]) == 200
    finally:
        totp.MAX_MIGRATION_ACCOUNTS = original


def test_more_than_one_code_in_a_picture_is_reported(env):
    accounts, *_ = env
    view = accounts.collect([KEY_URI, "otpauth://totp/B:b?secret=JBSWY3DPEHPK3PXP&issuer=B"])
    assert view["more_codes"] == 1
    assert accounts.collect([KEY_URI])["more_codes"] == 0


def test_breach_checks_skip_logins_that_need_their_real_password():
    from localvault.app.health import HealthService

    class Session:
        def all_entries(self):
            return [{"id": "a", "password": "placeholder-1", "tags": ["needs-password"]},
                    {"id": "b", "password": "real-pass-1", "tags": []}]

    assert HealthService._unique_passwords(Session(), {"a", "b"}) == 1
    assert HealthService._breach_passwords(Session(), {"a", "b"}) == {"b": "real-pass-1"}
