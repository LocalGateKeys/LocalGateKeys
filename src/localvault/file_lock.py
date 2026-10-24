"""Short, non-blocking per-file writer lock. No secrets in the lock file."""
from __future__ import annotations

import errno
import os
import time
from contextlib import contextmanager
from pathlib import Path

LOCK_WAIT_SECONDS = 2.0  # another writer finishing a save; longer than this is a real conflict

_CONTENTION = {errno.EACCES, errno.EDEADLK, errno.EAGAIN, errno.EWOULDBLOCK}


def _acquire(fd: int) -> None:
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            if os.name == 'nt':
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            # Only "someone else holds it" is worth waiting for; any other error is real.
            if exc.errno not in _CONTENTION or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


@contextmanager
def exclusive_writer(path: Path):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(path.with_name(path.name+'.lock')),os.O_RDWR|os.O_CREAT,0o600)
    handle=os.fdopen(fd,'r+b')
    held=False
    try:
        if os.name=='nt':
            import msvcrt
            if os.fstat(fd).st_size<1:
                handle.write(b'0');handle.flush()
            handle.seek(0)
        _acquire(fd)
        held=True
        yield
    finally:
        if held:
            if os.name=='nt':
                import msvcrt
                handle.seek(0);msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_UN)
        handle.close()
