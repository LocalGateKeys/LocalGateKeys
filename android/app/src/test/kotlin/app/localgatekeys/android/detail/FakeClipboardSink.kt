package app.localgatekeys.android.detail

/** The system clipboard as the app sees it (port of the Swift FakePasteboard): every write is kept in [history]. */
class FakeClipboardSink : ClipboardSink {
    data class Write(val text: String, val sensitive: Boolean)

    var text: String? = null
        private set
    val history = mutableListOf<Write>()
    var clears = 0
        private set

    override fun set(text: String, sensitive: Boolean) {
        this.text = text
        history.add(Write(text, sensitive))
    }

    override fun current(): String? = text

    override fun clear() {
        text = null
        clears++
    }

    /** Another app (or the person) copied something. */
    fun foreignCopy(s: String) {
        text = s
    }
}
