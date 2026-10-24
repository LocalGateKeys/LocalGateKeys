"""``Windows.ApplicationModel.StartupTask`` for the MSIX build, via ctypes.

A packaged app cannot start with Windows through the HKCU Run key: its
registry writes are virtualized and the package directory changes on every
update. It declares a ``windows.startupTask`` in AppxManifest.xml instead and
switches it with this WinRT API. Desktop (full-trust) apps get no consent
prompt from ``RequestEnableAsync``; a task the user turned off in Task Manager
or Settings stays ``DisabledByUser`` and only the user can turn it back on.

Standard library only. Interface ids and vtable order are from the Windows SDK
``windows.applicationmodel.h`` and ``asyncinfo.h``. Every call runs on its own
short-lived MTA thread so polling the async operation never depends on the
caller's (Tk, STA) message loop. Failures raise ``OSError``.
"""
from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from typing import TypeVar

DISABLED = 0
DISABLED_BY_USER = 1
ENABLED = 2
DISABLED_BY_POLICY = 3
ENABLED_BY_POLICY = 4
ENABLED_STATES = frozenset({ENABLED, ENABLED_BY_POLICY})

_CLASS_NAME = "Windows.ApplicationModel.StartupTask"
_IID_STARTUP_TASK_STATICS = "ee5b60bd-a148-41a7-b26e-e8b88a1e62f8"
_IID_ASYNC_INFO = "00000036-0000-0000-c000-000000000046"

# IUnknown 0-2, IInspectable 3-5.
_RELEASE = 2
_QUERY_INTERFACE = 0
_STATICS_GET_ASYNC = 7            # IStartupTaskStatics.GetAsync(HSTRING, IAsyncOperation<StartupTask>**)
_TASK_REQUEST_ENABLE_ASYNC = 6    # IStartupTask.RequestEnableAsync(IAsyncOperation<StartupTaskState>**)
_TASK_DISABLE = 7                 # IStartupTask.Disable()
_TASK_GET_STATE = 8               # IStartupTask.get_State(StartupTaskState*)
_ASYNC_GET_STATUS = 7             # IAsyncInfo.get_Status(AsyncStatus*)
_ASYNC_GET_ERROR_CODE = 8         # IAsyncInfo.get_ErrorCode(HRESULT*)
_ASYNC_CLOSE = 10                 # IAsyncInfo.Close()
_OPERATION_GET_RESULTS = 8        # IAsyncOperation<T>.GetResults(T*)

_ASYNC_STARTED, _ASYNC_COMPLETED = 0, 1
_RPC_E_CHANGED_MODE = -2147417850  # 0x80010106
_TIMEOUT_SECONDS = 10.0

T = TypeVar("T")


def _run_on_mta_thread(work: Callable[[], T]) -> T:
    outcome: dict[str, object] = {}

    def runner() -> None:
        try:
            outcome["value"] = _with_winrt(work)
        except BaseException as exc:  # re-raised on the calling thread
            outcome["error"] = exc

    thread = threading.Thread(target=runner, name="lgk-startup-task", daemon=True)
    thread.start()
    thread.join(_TIMEOUT_SECONDS + 5)
    if thread.is_alive():
        raise OSError("The Windows startup task did not respond.")
    if "error" in outcome:
        error = outcome["error"]
        if isinstance(error, OSError):
            raise error
        raise OSError(f"The Windows startup task failed: {error}") from error  # type: ignore[misc]
    return outcome["value"]  # type: ignore[return-value]


def _with_winrt(work: Callable[[], T]) -> T:
    import ctypes

    combase = ctypes.WinDLL("combase")
    combase.RoInitialize.argtypes = [ctypes.c_int]
    combase.RoInitialize.restype = ctypes.c_long
    result = combase.RoInitialize(1)  # RO_INIT_MULTITHREADED
    if result < 0 and result != _RPC_E_CHANGED_MODE:
        raise OSError(f"RoInitialize failed (0x{result & 0xFFFFFFFF:08X})")
    try:
        return work()
    finally:
        if result >= 0:
            combase.RoUninitialize()


def _guid(text: str):
    import ctypes

    class GUID(ctypes.Structure):
        _fields_ = [("data", ctypes.c_ubyte * 16)]

    value = GUID()
    ctypes.memmove(ctypes.byref(value), uuid.UUID(text).bytes_le, 16)
    return value


def _method(pointer, index: int, *argtypes, restype=None):
    import ctypes

    vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    prototype = ctypes.WINFUNCTYPE(restype or ctypes.HRESULT, ctypes.c_void_p, *argtypes)
    return prototype(vtable[index])


def _release(pointer) -> None:
    import ctypes

    if pointer:
        _method(pointer, _RELEASE, restype=ctypes.c_ulong)(pointer)


def _await(operation, result_type):
    """Poll an ``IAsyncOperation<T>`` to completion and return ``GetResults``."""
    import ctypes

    info = ctypes.c_void_p()
    _method(operation, _QUERY_INTERFACE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(
        operation, ctypes.byref(_guid(_IID_ASYNC_INFO)), ctypes.byref(info))
    try:
        status = ctypes.c_int(_ASYNC_STARTED)
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        while True:
            _method(info, _ASYNC_GET_STATUS, ctypes.POINTER(ctypes.c_int))(info, ctypes.byref(status))
            if status.value != _ASYNC_STARTED:
                break
            if time.monotonic() > deadline:
                raise OSError("The Windows startup task did not respond.")
            time.sleep(0.02)
        if status.value != _ASYNC_COMPLETED:
            code = ctypes.c_long(0)
            _method(info, _ASYNC_GET_ERROR_CODE, ctypes.POINTER(ctypes.c_long))(info, ctypes.byref(code))
            raise OSError(f"The Windows startup task failed (0x{code.value & 0xFFFFFFFF:08X})")
        value = result_type()
        _method(operation, _OPERATION_GET_RESULTS, ctypes.POINTER(result_type))(operation, ctypes.byref(value))
        return value
    finally:
        _method(info, _ASYNC_CLOSE)(info)
        _release(info)


def _hstring(text: str):
    import ctypes

    combase = ctypes.WinDLL("combase")
    combase.WindowsCreateString.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    combase.WindowsCreateString.restype = ctypes.HRESULT
    handle = ctypes.c_void_p()
    combase.WindowsCreateString(text, len(text), ctypes.byref(handle))
    return handle


def _delete_hstring(handle) -> None:
    import ctypes

    combase = ctypes.WinDLL("combase")
    combase.WindowsDeleteString.argtypes = [ctypes.c_void_p]
    combase.WindowsDeleteString(handle)


def _with_task(task_id: str, action: Callable[[object], T]) -> T:
    import ctypes

    combase = ctypes.WinDLL("combase")
    combase.RoGetActivationFactory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    combase.RoGetActivationFactory.restype = ctypes.HRESULT
    class_name = _hstring(_CLASS_NAME)
    task_name = _hstring(task_id)
    statics = ctypes.c_void_p()
    operation = ctypes.c_void_p()
    task = ctypes.c_void_p()
    try:
        combase.RoGetActivationFactory(class_name, ctypes.byref(_guid(_IID_STARTUP_TASK_STATICS)),
                                       ctypes.byref(statics))
        _method(statics, _STATICS_GET_ASYNC, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(
            statics, task_name, ctypes.byref(operation))
        task = _await(operation, ctypes.c_void_p)
        if not task:
            raise OSError(f"No startup task named {task_id!r} is declared in the package.")
        return action(task)
    finally:
        _release(task)
        _release(operation)
        _release(statics)
        _delete_hstring(task_name)
        _delete_hstring(class_name)


def _state_of(task) -> int:
    import ctypes

    state = ctypes.c_int(DISABLED)
    _method(task, _TASK_GET_STATE, ctypes.POINTER(ctypes.c_int))(task, ctypes.byref(state))
    return int(state.value)


def _request_enable(task) -> int:
    import ctypes

    operation = ctypes.c_void_p()
    _method(task, _TASK_REQUEST_ENABLE_ASYNC, ctypes.POINTER(ctypes.c_void_p))(task, ctypes.byref(operation))
    try:
        return int(_await(operation, ctypes.c_int).value)
    finally:
        _release(operation)


def _disable(task) -> int:
    _method(task, _TASK_DISABLE)(task)
    return _state_of(task)


def state(task_id: str) -> int:
    """Current ``StartupTaskState`` of the package's task."""

    return _run_on_mta_thread(lambda: _with_task(task_id, _state_of))


def request_enable(task_id: str) -> int:
    """Ask Windows to enable the task; returns the resulting state."""

    return _run_on_mta_thread(lambda: _with_task(task_id, _request_enable))


def disable(task_id: str) -> int:
    """Disable the task; returns the resulting state."""

    return _run_on_mta_thread(lambda: _with_task(task_id, _disable))
