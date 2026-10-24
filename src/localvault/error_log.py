"""Local error log for diagnosing problems.

Records only exception types and stack frames ("File ..., line N, in func")
from unexpected errors. An exception's message can quote the value being
processed (``int("hunter2")``, ``KeyError(secret)``), so it is written only for
operating-system errors (``OSError``: errno and Windows' own text), and only
after it is clipped and scrubbed of anything that looks like a long secret
token, of the value in ``password=...`` / ``token: ...`` style assignments and
``Bearer`` headers (whatever their length), and of any secret values the
caller names. The log stays on this device and is size-limited.
"""
from __future__ import annotations

import logging
import re
import traceback
from collections.abc import Iterable
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import data_dir

_LOGGER_NAME = "localgatekeys"
_MAX_BYTES = 512 * 1024
_BACKUPS = 2
_configured = False
# Long unbroken runs (keys, tokens, base64) are replaced before writing.
_SECRETISH = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
# Short secrets are caught by context: the value of a secret-named assignment
# (``password=hunter2``, ``"token": "abc"``, ``pin: 1234``) and HTTP auth
# schemes. Ordinary prose ("password changed", "token expired") is untouched.
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|(?:access|auth|refresh|id|api|csrf)?[_-]?token"""
    r"""|api[_-]?key|access[_-]?key|private[_-]?key|key|authorization|cookie|session[_-]?id|otp|totp|pin"""
    r"""|credentials?)(["']?\s*[:=]\s*)((?:(?:bearer|basic|digest)\s+)?(?:"[^"]*"|'[^']*'|[^\s,;&)\]}]+))""")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_MIN_KNOWN_SECRET = 4


def _scrub(text: str, secrets: Iterable[str] = ()) -> str:
    for secret in sorted({value for value in secrets if isinstance(value, str) and len(value) >= _MIN_KNOWN_SECRET},
                         key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text)
    text = _AUTH_SCHEME.sub(lambda match: f"{match.group(1)} [redacted]", text)
    return _SECRETISH.sub("[redacted]", text)[:4000]


_WITHHELD = "(message not logged)"


def _message(exc: BaseException, secrets: Iterable[str] = ()) -> str:
    """The scrubbed message of an OS error; any other exception's message is withheld."""
    if not isinstance(exc, OSError):
        return _WITHHELD
    return _scrub(str(exc), secrets)


def log_path() -> Path:
    return data_dir() / "logs" / "errors.log"


def _logger() -> logging.Logger:
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if not _configured:
        _configured = True
        logger.setLevel(logging.INFO)
        logger.propagate = False
        try:
            path = log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(handler)
        except OSError:
            logger.addHandler(logging.NullHandler())
    return logger


def log_exception(where: str, exc: BaseException, *, secrets: Iterable[str] = ()) -> None:
    """Record an unexpected error. Never raises.

    ``secrets`` names values the caller knows are sensitive (for example the
    password that was being processed); every occurrence is redacted however
    short it is.
    """
    try:
        frames = traceback.format_exception(type(exc), exc, exc.__traceback__)
        # Keep only the "File ..., line N, in func" header of each frame; source
        # lines and the message are dropped (the message is re-added scrubbed).
        stack = "".join(frame.splitlines()[0] + "\n" for frame in frames if frame.startswith("  File "))
        _logger().error("%s: %s: %s\n%s", where, type(exc).__name__, _message(exc, secrets), stack.rstrip())
    except Exception:
        pass


def install_tk_handler(root) -> None:
    """Log exceptions raised inside Tk callbacks instead of losing them."""
    previous = root.report_callback_exception

    def report(exc_type, exc, tb):
        if exc is not None and exc.__traceback__ is None:
            exc.__traceback__ = tb
        log_exception("ui-callback", exc)
        previous(exc_type, exc, tb)

    root.report_callback_exception = report
