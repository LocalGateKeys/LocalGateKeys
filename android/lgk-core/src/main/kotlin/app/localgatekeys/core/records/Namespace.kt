package app.localgatekeys.core.records

/** Synced record namespaces. */
enum class Namespace(val wire: String) {
    ENTRY("entry"),
    ITEM("item"),
    LICENSE("license"),

    /** The owner's emergency access plan (sub-plan 08), one state `heir:plan` ([app.localgatekeys.core.recovery.Heir]). */
    HEIR("heir"),
    ;

    companion object {
        fun fromWire(s: String): Namespace? = entries.firstOrNull { it.wire == s }
    }
}
