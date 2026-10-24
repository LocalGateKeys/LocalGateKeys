"""2FA QR import: real QR images decoded with OpenCV, from a pasted snip or camera frames."""
from __future__ import annotations

import base64
import json

import pytest
from test_app_login_extras import KDF, MASTER, Port, Sched, _migration_uri

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.login_editor import LoginEditorService
from localvault.app.login_extras import LoginExtrasService
from localvault.app.qr_import import QrImportService, make_decoder, otp_texts
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")

KEY_URI = "otpauth://totp/Alpha:ann?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


def qr_image(text, size=900):
    """A QR code on a big white 'screen', as a BGR image."""
    code = cv2.QRCodeEncoder.create().encode(text)
    code = cv2.resize(code, (400, 400), interpolation=cv2.INTER_NEAREST)
    screen = np.full((size, size * 16 // 9), 255, dtype=np.uint8)
    screen[200:600, 300:700] = code
    return cv2.cvtColor(screen, cv2.COLOR_GRAY2BGR)


def snip(image):
    """The data URL the page sends for a pasted PNG."""
    ok, data = cv2.imencode(".png", image)
    assert ok
    return "data:image/png;base64," + base64.b64encode(data.tobytes()).decode("ascii")


def blank():
    return np.full((720, 1280, 3), 200, dtype=np.uint8)


class Capture:
    def __init__(self, frames):
        self.frames = list(frames)
        self.released = False

    def read(self):
        return (True, self.frames.pop(0)) if self.frames else (True, blank())

    def set(self, *_args):
        return True

    def release(self):
        self.released = True


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port = Port()
    editor = LoginEditorService(controller, port, generate=lambda: "Generated-Pass-123!")
    extras = LoginExtrasService(controller, port, editor)

    def service(frames=()):
        capture = Capture(frames)
        qr = QrImportService(controller, editor, extras, emit=bus.emit,
                             open_camera=lambda _cv2, index: (capture, index), sleep=lambda _s: None)
        return qr, capture

    draft = editor.open_new()
    editor.update(draft["draft_id"], {"label": "Alpha", "urls": [{"url": "alpha.test", "match": "exact_origin"}]})
    return service, editor, draft["draft_id"], bus, controller


def test_decoder_reads_real_qr_codes_and_keeps_only_2fa_ones():
    assert make_decoder(cv2)(qr_image(KEY_URI)) == [KEY_URI]
    assert otp_texts(["https://example.test", f" {KEY_URI} ", KEY_URI, "OTPAUTH-MIGRATION://offline?data=x"]) == [
        KEY_URI, "OTPAUTH-MIGRATION://offline?data=x"]


def test_pasted_snip_puts_the_key_in_the_draft(env):
    service, editor, draft_id, _bus, _controller = env
    qr, _capture = service()
    result = qr.scan_image(draft_id, snip(qr_image(KEY_URI)))
    assert result["found"] == "key" and result["view"]["totp_configured"] is True
    assert "JBSWY3DP" not in json.dumps(result)
    assert editor._drafts[draft_id].draft.totp_text == KEY_URI


def test_a_tight_small_snip_is_still_read(env):
    service, editor, draft_id, _bus, _controller = env
    qr, _capture = service()
    code = cv2.QRCodeEncoder.create().encode(KEY_URI)
    small = cv2.cvtColor(cv2.copyMakeBorder(code, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255), cv2.COLOR_GRAY2BGR)
    assert qr.scan_image(draft_id, snip(small))["found"] == "key"


def test_pasted_google_export_lists_its_accounts(env):
    service, _editor, draft_id, _bus, _controller = env
    qr, _capture = service()
    result = qr.scan_image(draft_id, snip(qr_image(_migration_uri(b"0123456789", "ann@alpha.test", "Alpha"))))
    assert result["found"] == "accounts" and result["accounts"][0]["issuer"] == "Alpha"
    assert result["best"] == 0 and "secret" not in json.dumps(result)


def test_pasted_image_without_a_2fa_code_or_not_an_image(env):
    service, _editor, draft_id, _bus, _controller = env
    qr, _capture = service()
    with pytest.raises(ApiError) as missing:
        qr.scan_image(draft_id, snip(qr_image("https://not-a-2fa-code.test")))
    assert missing.value.code == "not_found"
    for bad in ("hello", "data:text/plain;base64,aGk=", "data:image/png;base64,not base64!",
                "data:image/png;base64," + base64.b64encode(b"not a png").decode()):
        with pytest.raises(ApiError) as invalid:
            qr.scan_image(draft_id, bad)
        assert invalid.value.code == "invalid"
    with pytest.raises(ApiError) as closed:
        qr.scan_image("no-such-editor", snip(qr_image(KEY_URI)))
    assert closed.value.code == "not_found"
    assert qr._busy.acquire(blocking=False)  # every failure released the scanner


def test_camera_scan_streams_previews_until_a_code_is_seen(env):
    service, editor, draft_id, bus, _controller = env
    qr, capture = service(frames=[blank(), blank(), qr_image(KEY_URI)])
    result = qr.scan_camera(draft_id)
    assert result["found"] == "key" and editor._drafts[draft_id].draft.totp_text == KEY_URI
    names = [name for name, _ in bus.events]
    assert "qr.frame" in names and bus.events[-1] == ("qr.status", {"status": "QR code read", "detail": "",
                                                                      "state": "success"})
    assert capture.released


def test_camera_scan_stops_when_cancelled_or_locked(env):
    service, _editor, draft_id, _bus, controller = env
    qr, capture = service()
    qr.cancel()
    qr._cancelled.set = lambda: None  # _start clears the flag; keep the cancel requested before the loop
    qr._cancelled.clear = lambda: None
    with pytest.raises(ApiError) as cancelled:
        qr.scan_camera(draft_id)
    assert cancelled.value.code == "cancelled" and capture.released
    assert qr.cancel in controller.on_lock
