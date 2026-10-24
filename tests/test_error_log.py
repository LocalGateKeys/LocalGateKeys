"""The local error log records failures without secret-looking values."""
from __future__ import annotations

import localvault.error_log as error_log


def test_log_exception_scrubs_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(error_log, "_configured", False)
    logger = error_log.logging.getLogger("localgatekeys")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    try:
        raise OSError("write failed for token abcdEFGH1234567890abcdEFGH1234")
    except OSError as exc:
        error_log.log_exception("test", exc)
    for handler in logger.handlers:
        handler.flush()
    text = error_log.log_path().read_text(encoding="utf-8")
    assert "write failed" in text and "[redacted]" in text
    assert "abcdEFGH1234567890" not in text
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
