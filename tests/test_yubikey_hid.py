"""YubiKey HMAC-SHA1 challenge-response over USB HID (``localvault.yubikey_hid``).

No hardware: ``FakeKey`` plays the YubiKey side of the OTP feature-report exchange (frame in
8-byte reports, status polling, response in 8-byte reports with a CRC) and computes HMAC-SHA1
the way a slot in variable-input mode does.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import threading
from pathlib import Path

import pytest

from localvault import yubikey_hid as yk
from localvault.yubikey_hid import YubiKeyError

ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "tests" / "vectors" / "composite_key" / "cases.json")
                    .read_text(encoding="utf-8"))["yubikey"]
RESET = bytes(7) + b"\xff"
RFC2202_KEY = bytes.fromhex("0b" * 20)
RFC2202_RESPONSE = "b617318655057264e28bc0b6fb378c8ef146be00"


def _crc(data: bytes) -> int:
    # Reference CRC (yubikey-manager yubikit/core/otp.py calculate_crc), kept separate from the
    # module under test.
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


class FakeKey:
    """The YubiKey side of the OTP HID protocol."""

    def __init__(self, slots=None, *, version=(5, 4, 3), serial=12345678, touch_polls=0,
                 device_touch_timeout=False, remove_after=None, write_busy=False):
        self.slots = {2: RFC2202_KEY} if slots is None else slots
        self.version = version
        self.serial = serial
        self.touch_polls = touch_polls
        self.device_touch_timeout = device_touch_timeout
        self.remove_after = remove_after
        self.write_busy = write_busy
        self.sent: list[bytes] = []
        self.frames: list[bytes] = []
        self.receives = 0
        self.closed = False
        self._frame = bytearray(70)
        self._chunks: list[bytes] | None = None
        self._next = 0
        self._waiting = 0

    def _status(self, status_byte: int = 0) -> bytes:
        return bytes([0, *self.version, 1, 0x03, 0x00, status_byte])

    def receive(self) -> bytes:
        self.receives += 1
        if self.remove_after is not None and self.receives > self.remove_after:
            raise OSError(1167, "The device is not connected.")
        if self.write_busy:
            return self._status(0x80)
        if self._chunks is None:
            return self._status()
        if self._waiting:
            self._waiting -= 1
            if self._waiting == 0 and self.device_touch_timeout:
                self._chunks = None  # the key gave up waiting for a touch
            return self._status(0x20)
        if self._next < len(self._chunks):
            chunk = self._chunks[self._next]
            report = chunk + bytes([0x40 | self._next])
            self._next += 1
            return report
        return bytes(7) + b"\x40"  # sequence back to 0: transfer complete

    def send(self, report: bytes) -> None:
        assert len(report) == 8
        if self.remove_after is not None and self.receives > self.remove_after:
            raise OSError(1167, "The device is not connected.")
        self.sent.append(bytes(report))
        if report == RESET:
            self._chunks = None
            return
        assert report[7] & 0x80
        seq = report[7] & 0x1F
        if seq == 0:
            self._frame = bytearray(70)
        self._frame[seq * 7:seq * 7 + 7] = report[:7]
        if seq == 9:
            self._process(bytes(self._frame))

    def _process(self, frame: bytes) -> None:
        self.frames.append(frame)
        payload, cmd = frame[:64], frame[64]
        assert struct.unpack("<H", frame[65:67])[0] == _crc(payload)
        if cmd == 0x10:
            body = self.serial.to_bytes(4, "big")
        elif cmd in (0x30, 0x38):
            secret = self.slots.get(1 if cmd == 0x30 else 2)
            if secret is None:
                return  # unconfigured slot: the key answers with a plain status report
            message = payload.rstrip(payload[-1:])  # variable-input mode
            body = hmac.new(secret, message, hashlib.sha1).digest()
            self._waiting = self.touch_polls
        else:
            raise AssertionError(f"unexpected command {cmd:#x}")
        data = body + struct.pack("<H", _crc(body) ^ 0xFFFF)
        data += bytes(-len(data) % 7)
        self._chunks = [data[i:i + 7] for i in range(0, len(data), 7)]
        self._next = 0

    def close(self) -> None:
        self.closed = True


class FakeBackend:
    def __init__(self, devices):
        self.devices = devices  # list of (HidDeviceInfo, FakeKey | None)

    def enumerate(self):
        return [info for info, _ in self.devices]

    def open(self, path):
        for info, key in self.devices:
            if info.path == path:
                if key is None:
                    raise YubiKeyError("busy")
                return key
        raise YubiKeyError("not_found")


def _info(path, vid=0x1050, usage_page=1, usage=6, feature=9):
    return yk.HidDeviceInfo(path=path, vendor_id=vid, product_id=0x0407, usage_page=usage_page,
                            usage=usage, feature_report_length=feature)


@pytest.fixture
def fake(monkeypatch):
    def install(key, path="\\\\?\\hid#vid_1050&pid_0407&mi_00#otp"):
        monkeypatch.setattr(yk, "_backend", FakeBackend([(_info(path), key)]))
        monkeypatch.setattr(yk, "POLL_INTERVAL", 0.001)
        monkeypatch.setattr(yk, "TOUCH_POLL_INTERVAL", 0.001)
        return path
    return install


def test_frame_and_crc_match_reference():
    # Expected bytes computed with yubikey-manager's own yubikit/core/otp.py (main 4ca60f70)
    # calculate_crc, _format_frame and _should_send: RFC 2202 case 1 ("Hi There"), slot 2.
    frame = yk.format_frame(0x38, b"Hi There".ljust(64, b"\0"))
    assert frame.hex() == "4869205468657265" + "00" * 56 + "380bac000000"
    assert [r.hex() for r in yk.frame_reports(frame)] == [
        "4869205468657280", "6500000000000081", "00380bac00000089"]
    padded = bytes(range(32)) + b"\x20" * 32
    assert yk.format_frame(0x30, padded)[64:].hex() == "30cead000000"
    assert yk.calculate_crc(b"Hi There".ljust(64, b"\0")) == 0xAC0B
    response = bytes.fromhex(RFC2202_RESPONSE + "5754")
    assert yk.calculate_crc(response) == yk.CRC_OK_RESIDUAL


def test_challenge_response_slot2(fake):
    key = FakeKey({2: VECTOR["hmac_secret"].encode()})
    path = fake(key)
    padded = bytes.fromhex(VECTOR["padded_challenge_hex"])
    assert yk.challenge_response(path, 2, padded).hex() == VECTOR["response_hex"]
    assert key.frames[-1][:64] == padded  # sent as given, no library padding
    assert key.frames[-1][64] == 0x38
    assert key.closed


def test_rfc2202_vector_and_wrong_length(fake):
    path = fake(FakeKey())
    assert yk.challenge_response(path, 2, b"Hi There".ljust(64, b"\0")).hex() == RFC2202_RESPONSE
    with pytest.raises(ValueError):
        yk.challenge_response(path, 2, bytes(32))
    with pytest.raises(ValueError):
        yk.challenge_response(path, 3, bytes(64))


def test_slot1_command_byte(fake):
    key = FakeKey({1: b"slot one secret"})
    path = fake(key)
    padded = bytes.fromhex(VECTOR["padded_challenge_hex"])
    expected = hmac.new(b"slot one secret", padded[:32], hashlib.sha1).digest()
    assert yk.challenge_response(path, 1, padded) == expected
    assert key.frames[-1][64] == 0x30


def test_touch_wait_then_success(fake):
    key = FakeKey(touch_polls=5)
    path = fake(key)
    assert yk.challenge_response(path, 2, b"Hi There".ljust(64, b"\0")).hex() == RFC2202_RESPONSE
    assert key._waiting == 0


def test_touch_timeout(fake):
    key = FakeKey(touch_polls=10**9)
    path = fake(key)
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64), timeout=0.05)
    assert err.value.code == "touch_timeout"
    assert key.sent[-1] == RESET and key.closed

    # The key's own touch timeout: it stops waiting and answers with a status report.
    key = FakeKey(touch_polls=3, device_touch_timeout=True)
    path = fake(key)
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64))
    assert err.value.code == "touch_timeout"


def test_slot_not_configured(fake):
    path = fake(FakeKey({1: b"only slot one"}))
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64))
    assert err.value.code == "slot_not_configured"


def test_hid_device_removed_midway(fake):
    key = FakeKey(touch_polls=10**9, remove_after=6)
    path = fake(key)
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64))
    assert err.value.code == "removed"
    assert key.closed


def test_cancel_event(fake):
    key = FakeKey(touch_polls=10**9)
    path = fake(key)
    cancel = threading.Event()
    threading.Timer(0.05, cancel.set).start()
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64), timeout=10.0, cancel=cancel)
    assert err.value.code == "cancelled"
    assert key.sent[-1] == RESET


def test_busy_and_not_found(fake, monkeypatch):
    path = fake(FakeKey(write_busy=True))
    monkeypatch.setattr(yk, "WRITE_READY_TRIES", 3)
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response(path, 2, bytes(64))
    assert err.value.code == "busy"
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response("\\\\?\\hid#gone", 2, bytes(64))
    assert err.value.code == "not_found"


def test_list_filters_yubico_vid(monkeypatch):
    good = FakeKey(version=(5, 7, 1), serial=31337)
    no_serial = FakeKey(serial=None)
    devices = [
        (_info("yubikey-otp"), good),
        (_info("other-vendor", vid=0x046D), FakeKey()),
        (_info("yubikey-fido", usage_page=0xF1D0, usage=1, feature=0), FakeKey()),
        (_info("yubikey-short-feature", feature=65), FakeKey()),
        (_info("yubikey-locked"), None),
        (_info("yubikey-no-serial"), no_serial),
    ]
    monkeypatch.setattr(yk, "_backend", FakeBackend(devices))

    original = FakeKey._process

    def process(self, frame):
        if self.serial is None and frame[64] == 0x10:
            self.frames.append(frame)
            return
        original(self, frame)

    monkeypatch.setattr(FakeKey, "_process", process)
    found = yk.list_devices()
    assert found == [
        yk.YubiKeyInfo(path="yubikey-otp", serial=31337, version=(5, 7, 1)),
        yk.YubiKeyInfo(path="yubikey-locked", serial=None, version=(0, 0, 0)),
        yk.YubiKeyInfo(path="yubikey-no-serial", serial=None, version=(5, 4, 3)),
    ]
    assert good.closed and good.frames[-1][64] == 0x10  # read-only serial query, nothing else


def test_non_windows_backend_is_empty(monkeypatch):
    monkeypatch.setattr(yk, "_backend", yk._NoHid())
    assert yk.list_devices() == []
    with pytest.raises(YubiKeyError) as err:
        yk.challenge_response("x", 2, bytes(64))
    assert err.value.code == "not_found"
