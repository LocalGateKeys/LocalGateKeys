"""Read a 2FA QR code from a pasted snip, a picture file or the webcam.

Into the open login editor, or (without an editor) into the Scan sheet, whose
accounts ``qr_accounts`` keeps and adds to logins.

The site's 2FA setup page (``otpauth://``) or Google Authenticator's
Transfer accounts > Export screen (``otpauth-migration://``) is decoded with
OpenCV on this PC. The app never captures the screen (see
tests/test_no_capture_primitives.py): the person snips the code themselves
(Win+Shift+S) and pastes the image into the editor. Pasted images and camera
frames live only in memory; during a camera scan the page gets ``qr.status``
updates and small ``qr.frame`` JPEG previews.
"""
from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from typing import Any

from ..api.result import ApiError
from ..totp import TotpError, parse_otpauth_uri
from .face_capture import _open_camera
from ..i18n import t

PREFIXES = ("otpauth://", "otpauth-migration://")
CAMERA_TIMEOUT_SECONDS = 90
STALL_SECONDS = 3
FRAME_INTERVAL = 0.12
PREVIEW_WIDTH = 360
MAX_IMAGE_BYTES = 12 * 1024 * 1024
# A pasted snip is a screenshot: bounded sides and pixels keep cv2.imdecode's buffer small.
MAX_IMAGE_SIDE = 16_384
MAX_IMAGE_PIXELS = 40_000_000
SMALL_SNIP = 400  # a tight snip is upscaled once before giving up
PRIVACY = "cameraView.noUpload"
CAMERA_HINT = ("qrImport.showTheQrCodeFrom")
NOT_IN_IMAGE = ("qrImport.no2faQrCodeWas")
NO_CAMERA_LIBS = "qrImport.qrScanningIsNotAvailable"


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# JPEG start-of-frame markers (SOF0-SOF15 without DHT, JPG and DAC).
_JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}


def _jpeg_size(raw: bytes) -> tuple[int, int] | None:
    """(width, height) from the first JPEG frame header, or None."""
    pos = 2
    while pos + 4 <= len(raw):
        if raw[pos] != 0xFF:
            return None
        marker = raw[pos + 1]
        if marker == 0xFF:  # fill byte
            pos += 1
            continue
        if marker in (0x01, *range(0xD0, 0xD8)):
            pos += 2
            continue
        if marker in (0xD9, 0xDA):  # end of image or start of scan before any frame header
            return None
        length = int.from_bytes(raw[pos + 2:pos + 4], "big")
        if length < 2:
            return None
        if marker in _JPEG_SOF:
            if pos + 9 > len(raw):
                return None
            return int.from_bytes(raw[pos + 7:pos + 9], "big"), int.from_bytes(raw[pos + 5:pos + 7], "big")
        pos += 2 + length
    return None


def image_size(raw: bytes) -> tuple[int, int] | None:
    """(width, height) of a PNG, JPEG or BMP from its header, or None for anything else.

    Pasted bytes are checked before OpenCV sees them, so only the three
    formats a screen snip produces reach a decoder, at a bounded size.
    """
    if raw[:8] == _PNG_MAGIC and len(raw) >= 24 and raw[12:16] == b"IHDR":
        return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
    if raw[:3] == b"\xff\xd8\xff":
        return _jpeg_size(raw)
    if raw[:2] == b"BM" and len(raw) >= 26:
        header = int.from_bytes(raw[14:18], "little")
        if header == 12:  # BITMAPCOREHEADER
            return int.from_bytes(raw[18:20], "little"), int.from_bytes(raw[20:22], "little")
        if header >= 40:
            return (abs(int.from_bytes(raw[18:22], "little", signed=True)),
                    abs(int.from_bytes(raw[22:26], "little", signed=True)))
    return None


def check_image(raw: bytes) -> None:
    """Refuse pasted bytes that are not a reasonably sized PNG, JPEG or BMP."""
    size = image_size(raw)
    if size is None:
        raise ApiError("invalid", t("qrImport.useAPngJpegOr"))
    width, height = size
    if not 0 < width <= MAX_IMAGE_SIDE or not 0 < height <= MAX_IMAGE_SIDE or width * height > MAX_IMAGE_PIXELS:
        raise ApiError("invalid", t("qrImport.thatImageIsTooLarge"))


def make_decoder(cv2: Any) -> Callable[[Any], list[str]]:
    """Decode every QR code in a BGR image. WeChat's detector copes best with camera photos."""
    detectors: list[Callable[[Any], list[str]]] = []
    wechat = getattr(cv2, "wechat_qrcode_WeChatQRCode", None)
    if wechat is not None:
        try:
            engine = wechat()
            detectors.append(lambda image: [str(t) for t in engine.detectAndDecode(image)[0] if t])
        except Exception:  # noqa: BLE001, S110 - fall back to the plain detector
            pass
    plain = cv2.QRCodeDetector()

    def classic(image: Any) -> list[str]:
        found, texts, *_ = plain.detectAndDecodeMulti(image)
        if found:
            return [str(t) for t in texts if t]
        text, *_ = plain.detectAndDecode(image)
        return [str(text)] if text else []

    detectors.append(classic)

    def decode(image: Any) -> list[str]:
        for detector in detectors:
            try:
                texts = detector(image)
            except Exception:  # noqa: BLE001, S112 - try the next detector
                continue
            if texts:
                return texts
        return []

    return decode


def otp_texts(texts: list[str]) -> list[str]:
    """Only 2FA codes, in order, without duplicates; any other QR code is ignored."""
    out: list[str] = []
    for text in texts:
        text = text.strip()
        if text.lower().startswith(PREFIXES) and text not in out:
            out.append(text)
    return out


def _load_cv() -> tuple[Any, Any]:
    try:
        import cv2
        import numpy as np
    except Exception:  # noqa: BLE001
        raise ApiError("unavailable", t(NO_CAMERA_LIBS)) from None
    return cv2, np


class QrImportService:
    def __init__(self, controller: Any, editor: Any, extras: Any, *,
                 emit: Callable[[str, dict[str, Any]], None],
                 accounts: Any = None,
                 load_cv: Callable[[], tuple[Any, Any]] = _load_cv,
                 open_camera: Callable[[Any, int], tuple[Any, int]] = _open_camera,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._controller = controller
        self._editor = editor
        self._extras = extras
        self._emit = emit
        self._accounts = accounts
        self._load_cv = load_cv
        self._open_camera = open_camera
        self._clock = clock
        self._sleep = sleep
        self._busy = threading.Lock()
        self._cancelled = threading.Event()
        self._switch = threading.Event()
        controller.on_lock.append(self.cancel)

    # ----------------------------------------------------------- control
    def cancel(self) -> dict[str, Any]:
        self._cancelled.set()
        return {}

    def switch_camera(self) -> dict[str, Any]:
        self._switch.set()
        return {}

    def _start(self, draft_id: str | None) -> None:
        """Claim the scanner. A lock that lands at any point from here on is kept.

        The flags are cleared right after taking ``_busy`` and before the
        unlock check, so a lock between the check and the clear is never
        lost (the lock sets ``_cancelled`` and ``is_unlocked`` turns False).
        """
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("qrImport.aQrScanIsAlready"))
        try:
            self._cancelled.clear()
            self._switch.clear()
            if not self._controller.is_unlocked():
                raise ApiError("locked", t("error.lockedProfile"))
            with self._controller.vault_lock:
                if draft_id is None:
                    self._sheet().require_pro()  # free plan: the upgrade screen, before any decoding
                else:
                    self._editor.view(draft_id)  # the editor must still be open
            if not self._controller.is_unlocked():  # locked while we waited for the vault
                raise ApiError("locked", t("error.lockedProfile"))
        except BaseException:
            self._busy.release()
            raise

    def _sheet(self) -> Any:
        if self._accounts is None:
            raise ApiError("unavailable", t(NO_CAMERA_LIBS))
        return self._accounts

    def _should_scan(self) -> bool:
        return not self._cancelled.is_set() and self._controller.is_unlocked()

    # ------------------------------------------------------------ result
    def _use(self, draft_id: str, texts: list[str]) -> dict[str, Any]:
        """Put a found code into the draft: one key directly, an export as an account list to choose from."""
        keys = [t for t in texts if t.lower().startswith("otpauth://")]
        with self._controller.vault_lock:
            if keys:
                try:
                    parse_otpauth_uri(keys[0])
                except TotpError as exc:
                    raise ApiError("invalid", t("qrAccounts.thatQrCodeIsNot", exc=exc)) from None
                return {"found": "key", "view": self._editor.update(draft_id, {"totp_text": keys[0]})}
            view = self._editor.view(draft_id)
            label = view.get("label") or view.get("label_hint") or ""
            origin = (view.get("urls") or [{}])[0].get("url", "") if view.get("urls") else ""
            return {"found": "accounts", **self._extras.ga_parse(texts[0], label=label, origin=origin)}

    # ------------------------------------------------------------- image
    @staticmethod
    def _image_bytes(data_url: str) -> bytes:
        head, sep, body = data_url.partition(",")
        if not sep or not head.lower().startswith("data:image/") or ";base64" not in head.lower():
            raise ApiError("invalid", t("qrImport.pasteAnImageOfThe"))
        if len(body) > MAX_IMAGE_BYTES * 4 // 3 + 4:
            raise ApiError("invalid", t("qrImport.thatImageIsTooLarge"))
        try:
            return base64.b64decode(body, validate=True)
        except ValueError:
            raise ApiError("invalid", t("qrImport.pasteAnImageOfThe")) from None

    def scan_image(self, draft_id: str, data_url: str) -> dict[str, Any]:
        """Decode a QR code the person snipped and pasted; the image is never saved."""
        # A locked vault (or a closed editor) is refused before the pasted
        # bytes are even parsed; the scanner is released on every path.
        self._start(draft_id)
        try:
            return self._use(draft_id, self._image_texts(data_url))
        finally:
            self._busy.release()

    def sheet_scan_image(self, data_url: str, token: str | None = None) -> dict[str, Any]:
        """Scan sheet: a pasted snip, a chosen picture file or a dropped one, held in memory only."""
        self._start(None)
        try:
            texts = self._image_texts(data_url)
            with self._controller.vault_lock:
                return self._sheet().collect(texts, token)
        finally:
            self._busy.release()

    def _image_texts(self, data_url: str) -> list[str]:
        """2FA texts in a PNG, JPEG or BMP data URL; type and size are checked here, not trusted from the page."""
        raw = b""
        try:
            raw = self._image_bytes(data_url)
            check_image(raw)
            cv2, np = self._load_cv()
            image = cv2.imdecode(np.frombuffer(raw, dtype=np.uint8), getattr(cv2, "IMREAD_COLOR", 1))
            if image is None:
                raise ApiError("invalid", t("share.thatImageCouldNotBe"))
            decode = make_decoder(cv2)
            texts = otp_texts(decode(image))
            height, width = image.shape[:2]
            if not texts and max(height, width) < SMALL_SNIP:
                texts = otp_texts(decode(cv2.resize(image, (width * 2, height * 2),
                                                    interpolation=getattr(cv2, "INTER_NEAREST", 0))))
            del image
            if not texts:
                raise ApiError("not_found", t(NOT_IN_IMAGE))
            return texts
        finally:
            del raw

    # ------------------------------------------------------------ camera
    def _say(self, status: str, detail: str = PRIVACY, state: str = "running") -> None:
        self._emit("qr.status", {"status": status, "detail": detail, "state": state})

    def scan_camera(self, draft_id: str) -> dict[str, Any]:
        self._start(draft_id)
        try:
            return self._use(draft_id, self._camera_texts())
        finally:
            self._busy.release()

    def sheet_scan_camera(self, token: str | None = None) -> dict[str, Any]:
        """Scan sheet: read a code from the webcam (the next part of an export with ``token``)."""
        self._start(None)
        try:
            texts = self._camera_texts()
            with self._controller.vault_lock:
                return self._sheet().collect(texts, token)
        finally:
            self._busy.release()

    def _camera_texts(self) -> list[str]:
        capture = None
        try:
            cv2, _np = self._load_cv()
            decode = make_decoder(cv2)
            self._say(t("cameraView.starting"))
            capture, index = self._camera(cv2, 0)
            self._say(t("qrImport.holdTheQrCodeUp"), t(CAMERA_HINT))
            started = last_frame = self._clock()
            last_preview = -FRAME_INTERVAL
            while self._should_scan():
                now = self._clock()
                if self._switch.is_set():
                    self._switch.clear()
                    capture.release()
                    capture = None
                    self._say(t("qrImport.switchingCamera"))
                    capture, index = self._camera(cv2, (index + 1) % 4)
                    started = last_frame = self._clock()
                    self._say(t("qrImport.holdTheQrCodeUp"), t(CAMERA_HINT))
                    continue
                if now - started > CAMERA_TIMEOUT_SECONDS:
                    self._say(t("qrImport.no2faQrCodeWas2"), "", "failed")
                    raise ApiError("not_found", t("qrImport.no2faQrCodeWas3"))
                ok, frame = capture.read()
                if not ok or frame is None:
                    if self._clock() - last_frame > STALL_SECONDS:
                        self._say(t("qrImport.theWebcamStoppedReturningImages"), "", "failed")
                        raise ApiError("unavailable", t("qrImport.theWebcamStoppedReturningImages2"))
                    self._sleep(0.08)
                    continue
                last_frame = self._clock()
                texts = otp_texts(decode(frame))
                if texts:
                    self._say(t("qrImport.qrCodeRead"), "", "success")
                    return texts
                if now - last_preview >= FRAME_INTERVAL:
                    last_preview = now
                    image = self._preview(cv2, frame)
                    if image:
                        self._emit("qr.frame", {"image": image})
                self._sleep(0.03)
            self._say(t("qrImport.scanCancelled"), "", "cancelled")
            raise ApiError("cancelled", t("error.cancelled"))
        finally:
            if capture is not None:
                try:
                    capture.release()
                except Exception:  # noqa: BLE001, S110
                    pass

    def _camera(self, cv2: Any, start: int) -> tuple[Any, int]:
        try:
            capture, index = self._open_camera(cv2, start)
        except Exception as exc:  # noqa: BLE001 - shown as the face check shows it
            self._say(str(exc), "", "failed")
            raise ApiError("unavailable", str(exc)) from None
        # Export codes are dense: ask for more pixels than the face check needs.
        try:
            capture.set(getattr(cv2, "CAP_PROP_FRAME_WIDTH", 3), 1280)
            capture.set(getattr(cv2, "CAP_PROP_FRAME_HEIGHT", 4), 720)
        except Exception:  # noqa: BLE001, S110 - the camera keeps its own size
            pass
        return capture, index

    @staticmethod
    def _preview(cv2: Any, frame: Any) -> str | None:
        try:
            height, width = frame.shape[:2]
            small = cv2.resize(frame, (PREVIEW_WIDTH, max(1, int(height * PREVIEW_WIDTH / max(width, 1)))))
            ok, data = cv2.imencode(".jpg", cv2.flip(small, 1), [int(getattr(cv2, "IMWRITE_JPEG_QUALITY", 1)), 70])
        except Exception:  # noqa: BLE001 - a preview failure only skips one frame
            return None
        if not ok:
            return None
        return "data:image/jpeg;base64," + base64.b64encode(data.tobytes()).decode("ascii")
