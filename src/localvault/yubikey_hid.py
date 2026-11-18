"""YubiKey HMAC-SHA1 challenge-response over USB HID (Windows, ctypes, no extra dependency).

The YubiKey's OTP interface is a HID keyboard; commands go through 8-byte feature reports.
The framing follows Yubico's BSD-2-licensed sources (read for reference, not copied):

- yubikey-manager ``yubikit/core/otp.py`` (main 4ca60f706af930459138d8dc0f0f953480e1c7a4):
  ``calculate_crc`` / ``check_crc`` (lines 61-77, CRC-16/X.25, residual 0xF0B8), frame sizes and
  status flags (lines 96-107), ``_should_send`` / ``_format_frame`` (lines 118-124),
  ``_await_ready_to_write`` / ``_send_frame`` / ``_read_frame`` / ``_reset_state`` (lines 206-275).
- yubikey-manager ``yubikit/yubiotp.py``: ``CHAL_HMAC_1 = 0x30``, ``CHAL_HMAC_2 = 0x38``,
  ``DEVICE_SERIAL = 0x10`` (lines 87-97), response CRC check (``_YubiOtpOtpBackend``, lines 665-669).
- yubikey-manager ``ykman/hid/windows.py``: setupapi enumeration, usage (1, 6) and the 9-byte
  feature reports (report ID 0 + 8 bytes).
- ykpers ``ykcore/ykcore.c`` (master db0c0d641d47ee52e43af94dcee603d76186b6d3): ``yk_write_to_key``
  (lines 672-740: CRC little-endian after the slot byte, all-zero parts skipped except the first
  and last, ``seq | SLOT_WRITE_FLAG``) and ``yk_wait_for_key_status`` (lines 520-570: touch wait).

A frame is 70 bytes: the 64-byte payload, the slot command, CRC16(payload) little-endian and 3
filler bytes. ``challenge_response`` sends the caller's 64 bytes exactly as given: the caller pads
(``composite_key.pad_challenge``, COMPOSITE_KEY_V1 §1.2); this module never pads. It only sends
the HMAC challenge and the read-only serial query, never a configuration command.
"""
from __future__ import annotations

import struct
import sys
import threading
import time
from dataclasses import dataclass
from threading import Event
from typing import Literal, Protocol

YUBICO_VID = 0x1050
USAGE_OTP = (0x01, 0x06)  # Generic Desktop / Keyboard
FEATURE_REPORT_LENGTH = 9  # report ID 0 + 8 bytes

FEATURE_RPT_SIZE = 8
FEATURE_RPT_DATA_SIZE = 7
SLOT_DATA_SIZE = 64
FRAME_SIZE = SLOT_DATA_SIZE + 6
FRAME_REPORTS = FRAME_SIZE // FEATURE_RPT_DATA_SIZE  # 10

RESP_PENDING_FLAG = 0x40
SLOT_WRITE_FLAG = 0x80
RESP_TIMEOUT_WAIT_FLAG = 0x20
SEQUENCE_MASK = 0x1F
CRC_OK_RESIDUAL = 0xF0B8

CMD_DEVICE_SERIAL = 0x10
CMD_CHAL_HMAC = {1: 0x30, 2: 0x38}
HMAC_RESPONSE_SIZE = 20
SERIAL_SIZE = 4

POLL_INTERVAL = 0.02
TOUCH_POLL_INTERVAL = 0.1
WRITE_READY_TRIES = 20
WRITE_READY_INTERVAL = 0.05
SERIAL_TIMEOUT = 1.0

_EXCHANGE = threading.Lock()  # one exchange at a time: interleaved frames would corrupt both


class YubiKeyError(Exception):
    """``code``: not_found, slot_not_configured, touch_timeout, removed, busy or cancelled."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class YubiKeyInfo:
    path: str
    serial: int | None
    version: tuple[int, int, int]


@dataclass(frozen=True)
class HidDeviceInfo:
    path: str
    vendor_id: int
    product_id: int
    usage_page: int
    usage: int
    feature_report_length: int


class _Transport(Protocol):
    def receive(self) -> bytes: ...  # one 8-byte feature report; OSError on I/O failure
    def send(self, report: bytes) -> None: ...  # one 8-byte feature report
    def close(self) -> None: ...


class _Backend(Protocol):
    def enumerate(self) -> list[HidDeviceInfo]: ...
    def open(self, path: str) -> _Transport: ...  # YubiKeyError("not_found" | "busy")


# --- framing ----------------------------------------------------------------------------------

def calculate_crc(data: bytes) -> int:
    """CRC-16/X.25 (ISO 13239) without the final inversion, as the YubiKey computes it."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


def format_frame(command: int, payload: bytes) -> bytes:
    if len(payload) != SLOT_DATA_SIZE:
        raise ValueError("Frame payload must be 64 bytes")
    return payload + struct.pack("<BH", command, calculate_crc(payload)) + bytes(3)


def frame_reports(frame: bytes) -> list[bytes]:
    """The feature reports carrying ``frame``: 7 data bytes + (0x80 | sequence)."""
    reports = []
    for seq in range(FRAME_REPORTS):
        part = frame[seq * FEATURE_RPT_DATA_SIZE:(seq + 1) * FEATURE_RPT_DATA_SIZE]
        if seq in (0, FRAME_REPORTS - 1) or any(part):
            reports.append(part + bytes([SLOT_WRITE_FLAG | seq]))
    return reports


# --- exchange ---------------------------------------------------------------------------------

def _receive(transport: _Transport) -> bytes:
    report = transport.receive()
    if len(report) != FEATURE_RPT_SIZE:
        raise OSError("Unexpected feature report size")
    return report


def _reset(transport: _Transport) -> None:
    """Tell the key to drop a pending response (yubikit ``_reset_state``)."""
    try:
        transport.send(bytes(FEATURE_RPT_DATA_SIZE) + b"\xff")
    except OSError:
        # Best-effort file/OS step: failure is harmless here, so it is ignored.
        pass


def _send_frame(transport: _Transport, frame: bytes) -> None:
    for report in frame_reports(frame):
        for _ in range(WRITE_READY_TRIES):
            if not _receive(transport)[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG:
                break
            time.sleep(WRITE_READY_INTERVAL)
        else:
            raise YubiKeyError("busy")
        transport.send(report)


def _read_response(transport: _Transport, expected: int, deadline: float,
                   cancel: Event | None) -> bytes:
    response = bytearray()
    seq = 0
    needs_touch = False
    while True:
        report = _receive(transport)
        status = report[FEATURE_RPT_DATA_SIZE]
        if status & RESP_PENDING_FLAG:
            if status & SEQUENCE_MASK == seq:
                response += report[:FEATURE_RPT_DATA_SIZE]
                seq += 1
            elif status & SEQUENCE_MASK == 0:  # transfer complete
                _reset(transport)
                break
        elif status == 0:  # a plain status report: the key has nothing to send
            if response:
                raise YubiKeyError("removed")
            raise YubiKeyError("touch_timeout" if needs_touch else "slot_not_configured")
        else:
            needs_touch = needs_touch or bool(status & RESP_TIMEOUT_WAIT_FLAG)
            interval = TOUCH_POLL_INTERVAL if needs_touch else POLL_INTERVAL
            if cancel is not None and cancel.wait(interval):
                _reset(transport)
                raise YubiKeyError("cancelled")
            if cancel is None:
                time.sleep(interval)
        if time.monotonic() >= deadline:
            _reset(transport)
            raise YubiKeyError("touch_timeout")
    if len(response) < expected + 2 or calculate_crc(bytes(response[:expected + 2])) != CRC_OK_RESIDUAL:
        raise YubiKeyError("removed")  # broken transfer
    return bytes(response[:expected])


def _command(transport: _Transport, command: int, payload: bytes, expected: int,
             timeout: float, cancel: Event | None = None) -> bytes:
    deadline = time.monotonic() + timeout
    _send_frame(transport, format_frame(command, payload))
    return _read_response(transport, expected, deadline, cancel)


def challenge_response(path: str, slot: Literal[1, 2], challenge64: bytes, *,
                       timeout: float = 15.0, cancel: Event | None = None) -> bytes:
    """The 20-byte HMAC-SHA1 response of ``slot`` to the already padded 64-byte challenge."""
    if slot not in CMD_CHAL_HMAC:
        raise ValueError("YubiKey slot must be 1 or 2")
    if len(challenge64) != SLOT_DATA_SIZE:
        raise ValueError("YubiKey challenge must be the 64-byte padded challenge")
    if not _EXCHANGE.acquire(blocking=False):
        raise YubiKeyError("busy")
    try:
        transport = _hid().open(path)
        try:
            return _command(transport, CMD_CHAL_HMAC[slot], bytes(challenge64),
                            HMAC_RESPONSE_SIZE, timeout, cancel)
        except OSError:
            raise YubiKeyError("removed") from None
        finally:
            transport.close()
    finally:
        _EXCHANGE.release()


def _is_otp_interface(info: HidDeviceInfo) -> bool:
    return (info.vendor_id == YUBICO_VID and (info.usage_page, info.usage) == USAGE_OTP
            and info.feature_report_length == FEATURE_REPORT_LENGTH)


def list_devices() -> list[YubiKeyInfo]:
    """Plugged-in YubiKeys' OTP interfaces; serial is None when the key hides it or is busy."""
    found = []
    for info in _hid().enumerate():
        if not _is_otp_interface(info):
            continue
        if not _EXCHANGE.acquire(blocking=False):
            found.append(YubiKeyInfo(info.path, None, (0, 0, 0)))
            continue
        try:
            found.append(_describe(info.path))
        except YubiKeyError as err:
            if err.code != "not_found":
                found.append(YubiKeyInfo(info.path, None, (0, 0, 0)))
        finally:
            _EXCHANGE.release()
    return found


def _describe(path: str) -> YubiKeyInfo:
    transport = _hid().open(path)
    version = (0, 0, 0)
    serial = None
    try:
        status = _receive(transport)
        version = (status[1], status[2], status[3])
        serial = int.from_bytes(_command(transport, CMD_DEVICE_SERIAL, bytes(SLOT_DATA_SIZE),
                                         SERIAL_SIZE, SERIAL_TIMEOUT), "big")
    except (OSError, YubiKeyError):
        # Expected failure for this optional step: fall back to the default behaviour.
        pass
    finally:
        transport.close()
    return YubiKeyInfo(path, serial, version)


# --- Windows HID (setupapi + hid.dll) ----------------------------------------------------------

class _NoHid:
    """Not Windows, or hid.dll could not be loaded: no YubiKeys."""

    def enumerate(self) -> list[HidDeviceInfo]:
        return []

    def open(self, path: str) -> _Transport:
        raise YubiKeyError("not_found")


_backend: _Backend | None = None


def _hid() -> _Backend:
    global _backend
    if _backend is None:
        try:
            _backend = _WinHid() if sys.platform == "win32" else _NoHid()
        except OSError:
            _backend = _NoHid()
    return _backend


ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
BUSY_ERRORS = {ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION}


class _WinTransport:
    def __init__(self, hid, kernel32, handle):
        self._hid = hid
        self._kernel32 = kernel32
        self._handle = handle

    def receive(self) -> bytes:
        import ctypes as ct
        buf = ct.create_string_buffer(FEATURE_REPORT_LENGTH)
        if not self._hid.HidD_GetFeature(self._handle, buf, FEATURE_REPORT_LENGTH):
            raise ct.WinError(ct.get_last_error())
        return buf.raw[1:]

    def send(self, report: bytes) -> None:
        import ctypes as ct
        buf = ct.create_string_buffer(b"\0" + report, FEATURE_REPORT_LENGTH)
        if not self._hid.HidD_SetFeature(self._handle, buf, FEATURE_REPORT_LENGTH):
            raise ct.WinError(ct.get_last_error())

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


class _WinHid:
    def __init__(self):
        import ctypes as ct
        import ctypes.wintypes as wt

        self._ct = ct

        class GUID(ct.Structure):
            _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                        ("Data4", ct.c_ubyte * 8)]

        class SP_DEVICE_INTERFACE_DATA(ct.Structure):  # noqa: N801 (Win32 name)
            _fields_ = [("cbSize", wt.DWORD), ("InterfaceClassGuid", GUID), ("Flags", wt.DWORD),
                        ("Reserved", ct.c_size_t)]

        class HIDD_ATTRIBUTES(ct.Structure):  # noqa: N801
            _fields_ = [("Size", wt.ULONG), ("VendorID", wt.USHORT), ("ProductID", wt.USHORT),
                        ("VersionNumber", wt.USHORT)]

        class HIDP_CAPS(ct.Structure):  # noqa: N801
            _fields_ = [("Usage", wt.USHORT), ("UsagePage", wt.USHORT),
                        ("InputReportByteLength", wt.USHORT), ("OutputReportByteLength", wt.USHORT),
                        ("FeatureReportByteLength", wt.USHORT), ("Reserved", wt.USHORT * 17),
                        ("NumberLinkCollectionNodes", wt.USHORT), ("NumberInputButtonCaps", wt.USHORT),
                        ("NumberInputValueCaps", wt.USHORT), ("NumberInputDataIndices", wt.USHORT),
                        ("NumberOutputButtonCaps", wt.USHORT), ("NumberOutputValueCaps", wt.USHORT),
                        ("NumberOutputDataIndices", wt.USHORT), ("NumberFeatureButtonCaps", wt.USHORT),
                        ("NumberFeatureValueCaps", wt.USHORT), ("NumberFeatureDataIndices", wt.USHORT)]

        self.GUID, self.IFACE, self.ATTRS, self.CAPS = GUID, SP_DEVICE_INTERFACE_DATA, HIDD_ATTRIBUTES, HIDP_CAPS
        # Private DLL handles: these declarations must not change ctypes.windll for other code.
        hid = ct.WinDLL("hid", use_last_error=True)
        setupapi = ct.WinDLL("setupapi", use_last_error=True)
        kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        handle = wt.HANDLE
        hid.HidD_GetHidGuid.argtypes = [ct.POINTER(GUID)]
        hid.HidD_GetHidGuid.restype = None
        hid.HidD_GetAttributes.argtypes = [handle, ct.POINTER(HIDD_ATTRIBUTES)]
        hid.HidD_GetAttributes.restype = wt.BOOLEAN
        hid.HidD_GetPreparsedData.argtypes = [handle, ct.POINTER(ct.c_void_p)]
        hid.HidD_GetPreparsedData.restype = wt.BOOLEAN
        hid.HidD_FreePreparsedData.argtypes = [ct.c_void_p]
        hid.HidD_FreePreparsedData.restype = wt.BOOLEAN
        hid.HidP_GetCaps.argtypes = [ct.c_void_p, ct.POINTER(HIDP_CAPS)]
        hid.HidP_GetCaps.restype = ct.c_long
        hid.HidD_GetFeature.argtypes = [handle, ct.c_void_p, wt.ULONG]
        hid.HidD_GetFeature.restype = wt.BOOLEAN
        hid.HidD_SetFeature.argtypes = [handle, ct.c_void_p, wt.ULONG]
        hid.HidD_SetFeature.restype = wt.BOOLEAN
        setupapi.SetupDiGetClassDevsW.argtypes = [ct.POINTER(GUID), wt.LPCWSTR, wt.HWND, wt.DWORD]
        setupapi.SetupDiGetClassDevsW.restype = handle
        setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
            handle, ct.c_void_p, ct.POINTER(GUID), wt.DWORD, ct.POINTER(SP_DEVICE_INTERFACE_DATA)]
        setupapi.SetupDiEnumDeviceInterfaces.restype = wt.BOOL
        setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
            handle, ct.POINTER(SP_DEVICE_INTERFACE_DATA), ct.c_void_p, wt.DWORD,
            ct.POINTER(wt.DWORD), ct.c_void_p]
        setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wt.BOOL
        setupapi.SetupDiDestroyDeviceInfoList.argtypes = [handle]
        setupapi.SetupDiDestroyDeviceInfoList.restype = wt.BOOL
        kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ct.c_void_p, wt.DWORD,
                                         wt.DWORD, handle]
        kernel32.CreateFileW.restype = handle
        kernel32.CloseHandle.argtypes = [handle]
        kernel32.CloseHandle.restype = wt.BOOL
        self._hid, self._setupapi, self._kernel32 = hid, setupapi, kernel32
        self._invalid = ct.c_void_p(-1).value

    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE = 0x1 | 0x2  # FILE_SHARE_READ | FILE_SHARE_WRITE
    _OPEN_EXISTING = 3
    _DIGCF = 0x02 | 0x10  # DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    _HIDP_STATUS_SUCCESS = 0x00110000

    def _create(self, path: str, access: int):
        handle = self._kernel32.CreateFileW(path, access, self._FILE_SHARE, None,
                                            self._OPEN_EXISTING, 0, None)
        if handle is None or handle == self._invalid:
            return None, self._ct.get_last_error()
        return handle, 0

    def _paths(self) -> list[str]:
        ct = self._ct
        guid = self.GUID()
        self._hid.HidD_GetHidGuid(ct.byref(guid))
        info_set = self._setupapi.SetupDiGetClassDevsW(ct.byref(guid), None, None, self._DIGCF)
        if info_set is None or info_set == self._invalid:
            return []
        paths = []
        try:
            index = 0
            while True:
                iface = self.IFACE()
                iface.cbSize = ct.sizeof(self.IFACE)
                if not self._setupapi.SetupDiEnumDeviceInterfaces(info_set, None, ct.byref(guid),
                                                                  index, ct.byref(iface)):
                    break
                index += 1
                needed = ct.c_ulong(0)
                self._setupapi.SetupDiGetDeviceInterfaceDetailW(info_set, ct.byref(iface), None, 0,
                                                                ct.byref(needed), None)
                if needed.value < 6:
                    continue
                buf = ct.create_string_buffer(needed.value)
                # SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize: 8 on 64-bit, 6 on 32-bit.
                struct.pack_into("<I", buf, 0, 8 if ct.sizeof(ct.c_void_p) == 8 else 6)
                if self._setupapi.SetupDiGetDeviceInterfaceDetailW(info_set, ct.byref(iface), buf,
                                                                   needed.value, None, None):
                    paths.append(ct.wstring_at(ct.addressof(buf) + 4))
        finally:
            self._setupapi.SetupDiDestroyDeviceInfoList(info_set)
        return paths

    def _describe(self, path: str, handle) -> HidDeviceInfo | None:
        ct = self._ct
        attrs = self.ATTRS()
        attrs.Size = ct.sizeof(self.ATTRS)
        if not self._hid.HidD_GetAttributes(handle, ct.byref(attrs)):
            return None
        usage_page = usage = feature = 0
        if attrs.VendorID == YUBICO_VID:
            preparsed = ct.c_void_p()
            if self._hid.HidD_GetPreparsedData(handle, ct.byref(preparsed)):
                try:
                    caps = self.CAPS()
                    if (self._hid.HidP_GetCaps(preparsed, ct.byref(caps)) & 0xFFFFFFFF
                            == self._HIDP_STATUS_SUCCESS):
                        usage_page, usage = caps.UsagePage, caps.Usage
                        feature = caps.FeatureReportByteLength
                finally:
                    self._hid.HidD_FreePreparsedData(preparsed)
        return HidDeviceInfo(path, attrs.VendorID, attrs.ProductID, usage_page, usage, feature)

    def enumerate(self) -> list[HidDeviceInfo]:
        devices = []
        for path in self._paths():
            # Access 0: enough for attributes and caps, and keyboards cannot be opened otherwise.
            handle, _ = self._create(path, 0)
            if handle is None:
                continue
            try:
                info = self._describe(path, handle)
            finally:
                self._kernel32.CloseHandle(handle)
            if info is not None:
                devices.append(info)
        return devices

    def open(self, path: str) -> _Transport:
        # Write access as yubikey-manager opens it; then access 0 (as hidapi falls back for
        # keyboards the system holds), which still allows feature reports.
        handle, error = self._create(path, self._GENERIC_WRITE)
        if handle is None:
            handle, error = self._create(path, 0)
        if handle is None:
            raise YubiKeyError("busy" if error in BUSY_ERRORS else "not_found")
        return _WinTransport(self._hid, self._kernel32, handle)
