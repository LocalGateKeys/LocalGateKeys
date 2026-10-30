"""UX workstream 9: share one item to a .lgkshare file and receive it in another profile."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import share
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.share_web import ShareService
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.upgrades = []

    def confirm(self, title, message):
        return True

    def show_upgrade(self, **kwargs):
        self.upgrades.append(kwargs)

    def ask_password(self, title, message):
        return SecretText.from_str(MASTER)

    def notify(self, kind, title, message):
        pass


class Dialogs:
    def __init__(self, path):
        self.path = path

    def open_file(self, title):
        return self.path

    def save_file(self, title, name):
        return self.path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(share, "KDF", {**share.KDF, "memory_cost_kib": 8192, "time_cost": 1})
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    entry_id = controller.session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}],
                                                   username="ann", password="pw-123456789012", label="Alpha")
    package = tmp_path / "Downloads" / "Alpha.lgkshare"
    package.parent.mkdir()
    port = Port()
    service = ShareService(controller, port, Dialogs(package))
    return SimpleNamespace(controller=controller, profiles=profiles, port=port, package=package, service=service,
                           ref={"source": "credential", "id": entry_id, "kind": "web"})


def _second_profile(env):
    second = env.profiles.create_profile("Second")
    env.controller.select_profile(second.id)
    env.controller.create(MASTER, MASTER)


def _send(env):
    started = env.service.start(env.ref)
    assert len(started["code"].split()) == 6 and started["qr"] is True
    assert env.service.qr(started["handle"])["image"].startswith("data:image/png;base64,")
    env.service.save_file(started["handle"])
    assert env.package.exists() and started["code"].encode() not in env.package.read_bytes()
    return started["code"]


def test_share_then_receive_into_another_profile(env):
    code = _send(env)
    _second_profile(env)
    got = env.service.receive_file()
    assert not env.package.exists()  # the delivered copy is gone
    assert [row["id"] for row in got["incoming"]] == [got["id"]]
    preview = env.service.preview(got["id"], code)
    assert preview["title"] == "Alpha" and preview["duplicate"] is False
    assert {"name": "Password", "value": "pw-123456789012", "secret": True} in preview["fields"]
    env.service.save(got["id"], code)
    assert env.controller.session.live_item_count() == 1
    assert env.service.incoming()["incoming"] == []
    with pytest.raises(ApiError):
        env.service.preview(got["id"], code)


def test_three_wrong_codes_delete_the_package(env):
    _send(env)
    _second_profile(env)
    got = env.service.receive_file()
    wrong = share.generate_code()
    for _ in range(2):
        with pytest.raises(ApiError) as exc:
            env.service.preview(got["id"], wrong)
        assert exc.value.code == "wrong_code"
    with pytest.raises(ApiError) as exc:
        env.service.preview(got["id"], wrong)
    assert exc.value.code == "deleted"
    assert env.service.incoming()["incoming"] == []


def test_reject_deletes_and_same_package_cannot_return(env, tmp_path):
    code = _send(env)
    data = env.package.read_bytes()
    _second_profile(env)
    got = env.service.receive_file()
    env.service.reject(got["id"])
    assert env.service.incoming()["incoming"] == []
    env.package.write_bytes(data)
    with pytest.raises(ApiError) as exc:
        env.service.receive_file()
    assert exc.value.code == "already_opened"
    assert code


def test_free_limit_keeps_the_package(env, monkeypatch):
    code = _send(env)
    _second_profile(env)
    got = env.service.receive_file()
    monkeypatch.setattr(type(env.controller.session), "item_limit", property(lambda self: 0), raising=False)
    with pytest.raises(ApiError) as exc:
        env.service.save(got["id"], code)
    assert exc.value.code == "item_limit" and env.port.upgrades
    assert [row["id"] for row in env.service.incoming()["incoming"]] == [got["id"]]


def test_passkeys_cannot_be_shared(env):
    with pytest.raises(ApiError) as exc:
        env.service.start({"source": "typed", "id": "x", "kind": "passkey"})
    assert exc.value.code == "not_shareable"


def test_typed_item_round_trip(env):
    note_id = env.controller.session.item_service.create_note("Door code", "4711")
    env.ref = {"source": "typed", "id": note_id, "kind": "note"}
    code = _send(env)
    _second_profile(env)
    got = env.service.receive_file()
    preview = env.service.preview(got["id"], code)
    assert preview["kind"] == "note" and any(f["value"] == "4711" for f in preview["fields"])
    env.service.save(got["id"], code)
    items = env.controller.session.item_service.list_items(kinds=["note"])
    assert [i["title"] for i in items] == ["Door code"] and items[0]["id"] != note_id


# ------------------------------------------------- every platform's packages
VECTORS = json.loads((Path(__file__).parent / "vectors" / "share" / "v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def receiver(tmp_path, monkeypatch):
    """A profile that receives the committed vectors (real v1 KDF parameters) at the vectors' time."""
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    service = ShareService(controller, Port(), Dialogs(tmp_path / "x.lgkshare"),
                           clock=lambda: VECTORS["opens"][0]["now"])
    return SimpleNamespace(controller=controller, service=service)


def _saved(env, case):
    got = env.service.receive_text(case["package"])
    assert got["sender"] == case["sender"]
    preview = env.service.preview(got["id"], case["code"])
    assert preview["fields"]
    env.service.save(got["id"], case["code"])
    session = env.controller.session
    kind = case["item"]["kind"]
    if kind in ("web", "desktop"):
        rows = list(session._require_payload()["entries"])
    else:
        rows = session.item_service.list_items(kinds=[kind])
    assert len(rows) == 1 and rows[0]["id"] != case["item"]["id"]
    return rows[0]


@pytest.mark.parametrize("case", VECTORS["opens"], ids=lambda c: c["name"])
def test_every_vector_kind_saves_on_windows(receiver, case):
    row = _saved(receiver, case)
    if case["item"]["kind"] == "web":
        assert row["scope"]["urls"] == case["item"]["scope"]["urls"]  # starts_with and host rows kept
        assert row["policy"]["sign_in"] == "never"  # never auto sign in after a share
    elif case["item"]["kind"] != "desktop":
        assert row["title"] == case["item"]["title"]


@pytest.mark.parametrize("case", VECTORS["legacy"], ids=lambda c: c["name"])
def test_display_shape_from_early_builds_is_converted_and_saved(receiver, case):
    row = _saved(receiver, case)
    if case["item"]["kind"] == "web":
        assert row["scope"]["origin"] == case["stored"]["scope"]["origin"]
        assert row["scope"]["urls"] == case["stored"]["scope"]["urls"]
    else:
        assert row["payload"]["ssid"] == case["stored"]["payload"]["ssid"]


def test_package_from_pasted_qr_text_rejects_other_text(receiver):
    with pytest.raises(ApiError) as exc:
        receiver.service.receive_text("lgkshare-code:maple-river-onion-seven-lamp-quote")
    assert exc.value.code == "bad_code"
    with pytest.raises(ApiError) as exc:
        receiver.service.receive_text("otpauth://totp/x?secret=AAAA")
    assert exc.value.code == "malformed"


def test_qr_image_paste_finds_the_package(receiver, monkeypatch):
    case = VECTORS["opens"][0]
    import localvault.app.qr_import as qr

    monkeypatch.setattr(qr, "check_image", lambda raw: None)
    monkeypatch.setattr(qr, "_load_cv", lambda: (SimpleNamespace(imdecode=lambda *a: object(), IMREAD_COLOR=1),
                                                 SimpleNamespace(frombuffer=lambda *a, **k: b"", uint8=None)))
    monkeypatch.setattr(qr, "make_decoder", lambda cv2: lambda image: ["otpauth://x", case["package"]])
    got = receiver.service.receive_qr_image("data:image/png;base64,AAAA")
    assert got["id"] == case["id"]


def test_three_wrong_codes_burn_the_package_id(receiver):
    case = VECTORS["opens"][0]
    got = receiver.service.receive_text(case["package"])
    wrong = "maple river onion seven lamp quick"
    for _ in range(3):
        with pytest.raises(ApiError):
            receiver.service.preview(got["id"], wrong)
    with pytest.raises(ApiError) as exc:  # delivering it again does not reset the count
        receiver.service.receive_text(case["package"])
    assert exc.value.code == "already_opened"


def test_local_references_do_not_travel():
    from localvault.app.share_web import _incoming, _outgoing

    card = {"kind": "card", "id": "x", "title": "c", "payload": {"billing_address_id": "abc", "number": "1"}}
    lic = {"kind": "license", "id": "y", "title": "l", "payload": {"document_ids": ["d"]}}
    desk = {"kind": "desktop", "id": "z", "scope": {"exe_path": "a.exe", "browser_approvals": ["x"]}}
    assert _outgoing(card)["payload"]["billing_address_id"] == ""
    assert _outgoing(lic)["payload"]["document_ids"] == []
    assert "browser_approvals" not in _outgoing(desk)["scope"]
    assert _incoming({**lic, "revision": 9, "collection_ids": ["c"]}).keys() == {"kind", "id", "title", "payload"}
