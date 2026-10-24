package app.localgatekeys.core.lan

/** A refused LAN sync step or message; [reason] is a stable code (Swift `LanSyncError`, desktop `LanSyncError`). */
class LanSyncException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")
