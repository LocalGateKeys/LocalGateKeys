"""Thread ownership/cancellation tests, independent of Windows or a camera."""
import threading

from localvault.auth_task import AuthTask
from localvault.windows_hello import HelloError


def test_success_transfers_exactly_once():
    value = object(); disposed = []
    task = AuthTask(lambda _cancel: value, disposed.append)
    task.thread.join(2)
    assert task.poll() == (True, value, None)
    assert task.poll() == (False, None, None)
    task.cancel()
    assert not disposed


def test_cancellation_disposes_late_worker_result():
    started = threading.Event(); release = threading.Event()
    value = object(); disposed = []
    def work(cancel):
        started.set(); assert release.wait(2)
        assert cancel.is_set()
        return value
    task = AuthTask(work, disposed.append)
    assert started.wait(2)
    task.cancel(); release.set(); task.thread.join(2)
    assert disposed == [value]
    assert task.poll() == (False, None, None)
    task.cancel(); assert disposed == [value]


def test_cancel_disposes_completed_but_unpolled_result():
    value = object(); disposed = []
    task = AuthTask(lambda _cancel: value, disposed.append)
    task.thread.join(2)
    task.cancel()
    assert disposed == [value]
    assert task.poll() == (False, None, None)


def test_error_messages_are_safe_not_traceback_objects():
    def fail(_cancel):
        raise RuntimeError("DO-NOT-EXPOSE-SECRET")
    task = AuthTask(fail, lambda _: None); task.thread.join(2)
    ready, result, error = task.poll()
    assert ready and result is None and isinstance(error, str)
    assert "DO-NOT-EXPOSE-SECRET" not in error


def test_safe_native_error_message_survives():
    def fail(_cancel):
        raise HelloError("Windows Hello test cancellation")
    task = AuthTask(fail, lambda _: None); task.thread.join(2)
    assert task.poll() == (True, None, "Windows Hello test cancellation")
