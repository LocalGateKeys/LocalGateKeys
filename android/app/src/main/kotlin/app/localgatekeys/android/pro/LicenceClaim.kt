package app.localgatekeys.android.pro

import android.content.Context
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL as JavaUrl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** The Worker's answer to a claim: the licence text, try again at the next launch, or never again (revoked). */
sealed interface ClaimResult {
    data class Licence(val text: String) : ClaimResult {
        override fun toString(): String = "Licence(…)"
    }

    data object RetryLater : ClaimResult

    data object Refused : ClaimResult
}

/** Trades the Play purchase token for a desktop licence (`POST /play/claim`). */
interface LicenceClaiming {
    suspend fun claim(purchaseToken: String): ClaimResult
}

/** [RETRY]: a claim failed (offline, 5xx, 429); the next launch tries again. [REFUSED]: the Worker said 403. */
enum class ClaimFlag { NONE, RETRY, REFUSED }

/** Where [ClaimFlag] survives a restart. */
interface ClaimFlagStore {
    fun read(): ClaimFlag
    fun write(flag: ClaimFlag)
}

class MemoryClaimFlags : ClaimFlagStore {
    @Volatile private var flag = ClaimFlag.NONE
    override fun read(): ClaimFlag = flag
    override fun write(flag: ClaimFlag) {
        this.flag = flag
    }
}

/** The flag in the app's own preferences (nothing secret: no token, no licence). */
class PrefsClaimFlags(context: Context) : ClaimFlagStore {
    private val prefs = context.getSharedPreferences("licence_claim", Context.MODE_PRIVATE)
    override fun read(): ClaimFlag = runCatching { ClaimFlag.valueOf(prefs.getString(KEY, null) ?: "NONE") }.getOrDefault(ClaimFlag.NONE)
    override fun write(flag: ClaimFlag) {
        prefs.edit().putString(KEY, flag.name).apply()
    }

    private companion object {
        const val KEY = "flag"
    }
}

/** The desktop paste form (`licensing.encode_paste` / `parse_text`): `LGK1-` + unpadded base64url of the canonical bundle. */
object LicenceText {
    const val PREFIX = "LGK1-"

    fun encode(bundle: JsonValue): String = PREFIX + Base64Url.encodeNoPad(CanonicalJson.encode(bundle, Dialect.UTF8))

    /** The bundle, tolerating wrapping and a trailing dot like the desktop; null for anything else. */
    fun decode(text: String): JsonValue? {
        val t = text.trim().removePrefix("﻿").trim()
        if (!t.startsWith(PREFIX)) return null
        val body = t.substring(PREFIX.length).filterNot { it.isWhitespace() }.trimEnd('.')
        if (body.isEmpty()) return null
        val raw = Base64Url.decodeLenient(body, MAX_BYTES) ?: return null
        return try {
            CanonicalJson.parse(raw) as? JsonValue.Obj
        } catch (e: Exception) {
            null
        }
    }

    private const val MAX_BYTES = 16 * 1024
}

/** The Worker over plain [HttpURLConnection] (no network library, no telemetry: the token and product id only). */
class HttpLicenceClaim(private val url: String = URL) : LicenceClaiming {
    override suspend fun claim(purchaseToken: String): ClaimResult = withContext(Dispatchers.IO) {
        val c = try {
            JavaUrl(url).openConnection() as HttpURLConnection
        } catch (e: IOException) {
            return@withContext ClaimResult.RetryLater
        }
        try {
            c.requestMethod = "POST"
            c.connectTimeout = TIMEOUT_MS
            c.readTimeout = TIMEOUT_MS
            c.doOutput = true
            c.useCaches = false
            c.instanceFollowRedirects = false
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(requestBody(purchaseToken)) }
            val code = c.responseCode
            val body = if (code == 200) c.inputStream.use { it.readBytes() } else ByteArray(0)
            result(code, body)
        } catch (e: IOException) {
            ClaimResult.RetryLater
        } finally {
            c.disconnect()
        }
    }

    companion object {
        const val URL = "https://licenses.localgatekeys.app/play/claim"
        private const val TIMEOUT_MS = 15_000

        /** `{"purchaseToken": "...", "productId": "pro_unlimited"}` (spec 4b). */
        fun requestBody(purchaseToken: String): ByteArray = CanonicalJson.encode(
            JsonValue.Obj(
                mapOf(
                    "purchaseToken" to JsonValue.Str(purchaseToken),
                    "productId" to JsonValue.Str(PlayBillingPurchases.PRODUCT_ID),
                ),
            ),
            Dialect.UTF8,
        )

        /** `200 {"licence": "LGK1-..."}`; `403` revoked (stop); anything else (400, 429, 5xx, a bad body) retries. */
        fun result(code: Int, body: ByteArray): ClaimResult {
            if (code == 403) return ClaimResult.Refused
            if (code != 200) return ClaimResult.RetryLater
            val text = try {
                ((CanonicalJson.parse(body) as? JsonValue.Obj)?.fields?.get("licence") as? JsonValue.Str)?.v
            } catch (e: Exception) {
                null
            }
            return if (text.isNullOrEmpty()) ClaimResult.RetryLater else ClaimResult.Licence(text)
        }
    }
}
