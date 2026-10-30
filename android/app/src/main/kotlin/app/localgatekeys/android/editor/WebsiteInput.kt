package app.localgatekeys.android.editor

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.OriginException

/** Why the Website field was refused. */
sealed interface WebsiteInputError {
    /** Desktop web logins always have an origin (`Normalise.entry` refuses an empty one). */
    data object Required : WebsiteInputError

    /** [http] true: a plain http:// address on a public host; otherwise just not a website. */
    data class Invalid(val http: Boolean) : WebsiteInputError

    data object NeedsPunycode : WebsiteInputError
}

class WebsiteInputException(val error: WebsiteInputError) : Exception(error.toString())

/**
 * The editor's Website field. People type `github.com` or paste a full address; the record stores the exact origin
 * (`scheme://host[:port]`) that core `Origin.canonicalize` accepts. Before canonicalising: trim, add `https://` when no
 * scheme is given, and drop any path, query or fragment. Port of `ios/App/Editor/WebsiteInput.swift`.
 */
object WebsiteInput {
    /** The text under the Website field for [error]; null for [WebsiteInputError.NeedsPunycode] (the editor words that itself). */
    fun message(error: WebsiteInputError, t: Txt): String? = when (error) {
        WebsiteInputError.Required -> t.s(R.string.website_required)
        is WebsiteInputError.Invalid -> t.s(if (error.http) R.string.website_http_message else R.string.website_invalid)
        WebsiteInputError.NeedsPunycode -> null
    }

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
        if (t.codePoints().anyMatch { isWhiteSpace(it) || it < 0x20 || it == 0x7F }) throw invalid(false)
        if (!t.contains("://")) t = "https://" + (if (t.startsWith("//")) t.substring(2) else t)
        val sep = t.indexOf("://")
        if (sep < 0) throw invalid(false)
        val rest = t.substring(sep + 3)
        val authority = rest.takeWhile { it != '/' && it != '?' && it != '#' }
        if (authority.any { it.code < 0x80 && it !in hostChars }) throw invalid(false)
        val candidate = t.substring(0, sep + 3) + authority
        return try {
            Origin.canonicalize(candidate)
        } catch (e: OriginException) {
            when (e.kind) {
                OriginException.Kind.NEEDS_PUNYCODE -> throw WebsiteInputException(WebsiteInputError.NeedsPunycode)
                // canonicalize's own wording for http on a public host; every other refusal gets the plain hint.
                OriginException.Kind.INVALID ->
                    throw invalid((e.message ?: "").startsWith("Plain HTTP"))
            }
        } catch (e: Exception) {
            throw invalid(false)
        }
    }

    private fun invalid(http: Boolean) = WebsiteInputException(WebsiteInputError.Invalid(http))
}
