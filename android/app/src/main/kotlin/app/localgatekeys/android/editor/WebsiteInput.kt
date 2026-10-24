package app.localgatekeys.android.editor

import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.OriginException

/** Why the Website field was refused. */
sealed interface WebsiteInputError {
    /** Desktop web logins always have an origin (`Normalise.entry` refuses an empty one). */
    data object Required : WebsiteInputError

    data class Invalid(val message: String) : WebsiteInputError

    data object NeedsPunycode : WebsiteInputError
}

class WebsiteInputException(val error: WebsiteInputError) : Exception(error.toString())

/**
 * The editor's Website field. People type `github.com` or paste a full address; the record stores the exact origin
 * (`scheme://host[:port]`) that core `Origin.canonicalize` accepts. Before canonicalising: trim, add `https://` when no
 * scheme is given, and drop any path, query or fragment. Port of `ios/App/Editor/WebsiteInput.swift`.
 */
object WebsiteInput {
    const val REQUIRED_MESSAGE = "Website is required"
    const val INVALID_MESSAGE = "Enter a website like github.com"
    const val HTTP_MESSAGE = "Use https:// for this website. Plain http:// works only for localhost."

    /** ASCII characters that may appear in what is typed for the host and port. */
    private val hostChars: Set<Char> =
        (('a'..'z') + ('A'..'Z') + ('0'..'9') + "-._:[]@%~".toList()).toSet()

    /** Unicode White_Space (Swift `properties.isWhitespace`). */
    internal fun isWhiteSpace(cp: Int): Boolean =
        Character.isWhitespace(cp) || Character.isSpaceChar(cp) || cp == 0x85

    /** Swift `trimmingCharacters(in: .whitespacesAndNewlines)`. */
    internal fun trimmed(text: String): String {
        var lo = 0
        var hi = text.length
        while (lo < hi && isWhiteSpace(text.codePointAt(lo))) lo += Character.charCount(text.codePointAt(lo))
        while (hi > lo && isWhiteSpace(text.codePointBefore(hi))) hi -= Character.charCount(text.codePointBefore(hi))
        return text.substring(lo, hi)
    }

    fun origin(text: String): String {
        var t = trimmed(text)
        if (t.isEmpty()) throw WebsiteInputException(WebsiteInputError.Required)
        if (t.codePoints().anyMatch { isWhiteSpace(it) || it < 0x20 || it == 0x7F }) throw invalid(INVALID_MESSAGE)
        if (!t.contains("://")) t = "https://" + (if (t.startsWith("//")) t.substring(2) else t)
        val sep = t.indexOf("://")
        if (sep < 0) throw invalid(INVALID_MESSAGE)
        val rest = t.substring(sep + 3)
        val authority = rest.takeWhile { it != '/' && it != '?' && it != '#' }
        if (authority.any { it.code < 0x80 && it !in hostChars }) throw invalid(INVALID_MESSAGE)
        val candidate = t.substring(0, sep + 3) + authority
        return try {
            Origin.canonicalize(candidate)
        } catch (e: OriginException) {
            when (e.kind) {
                OriginException.Kind.NEEDS_PUNYCODE -> throw WebsiteInputException(WebsiteInputError.NeedsPunycode)
                // canonicalize's own wording for http on a public host; every other refusal gets the plain hint.
                OriginException.Kind.INVALID ->
                    throw invalid(if ((e.message ?: "").startsWith("Plain HTTP")) HTTP_MESSAGE else INVALID_MESSAGE)
            }
        } catch (e: Exception) {
            throw invalid(INVALID_MESSAGE)
        }
    }

    private fun invalid(message: String) = WebsiteInputException(WebsiteInputError.Invalid(message))
}
