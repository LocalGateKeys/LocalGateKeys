package app.localgatekeys.core.records

/** Synced record namespaces. */
enum class Namespace(val wire: String) {
    ENTRY("entry"),
    ITEM("item"),
    LICENSE("license"),
    ;

    companion object {
        fun fromWire(s: String): Namespace? = entries.firstOrNull { it.wire == s }
    }
}
