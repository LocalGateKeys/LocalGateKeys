"""Find again: the not-this-device refusal reaches the page as clear copy."""
from localvault.app.sync_view import error_text
from localvault.sync.lan_sync import LanSyncError


def test_not_this_device_has_its_own_text():
    text = error_text(LanSyncError("not-this-device", "x"))
    assert "not paired with" in text and "error log" not in text
