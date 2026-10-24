package app.localgatekeys.core.group

/** A sealed-view format error; [reason] is the desktop `SyncFormatError.reason` string. */
class SyncFormatException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")
