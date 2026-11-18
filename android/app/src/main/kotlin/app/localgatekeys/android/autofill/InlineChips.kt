package app.localgatekeys.android.autofill

/**
 * Keyboard (inline) suggestions, Android 11+ (review 2026-11-15 UX 2): which of the keyboard's presentation specs the
 * dataset at [index] uses, or null for no chip. No chip when "Show in keyboard" is off ([enabled]), the keyboard asked
 * for none ([specCount] 0) or the keyboard's limit ([maxChips]) is reached. Past the last spec, the last one is reused
 * (the platform's rule).
 */
object InlineChips {
    fun specIndex(enabled: Boolean, specCount: Int, maxChips: Int, index: Int): Int? =
        if (!enabled || specCount <= 0 || index < 0 || index >= maxChips) null else minOf(index, specCount - 1)
}
