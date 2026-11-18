package app.localgatekeys.android.security

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/** Why a breach check did not run or did not finish (iPhone `BreachCheckError`). Carries no password or hash. */
class BreachCheckException(val kind: Kind) : Exception(kind.name) {
    enum class Kind { STRICT_OFFLINE, DISABLED, FAILED }
}

/** One GET to the range API. */
interface BreachTransport {
    suspend fun get(url: String, headers: Map<String, String>): ByteArray
}

/** HttpsURLConnection transport: 10 s timeouts, redirects refused, at most [MAX_BYTES] read, status 200 only. */
class HttpsBreachTransport : BreachTransport {
    override suspend fun get(url: String, headers: Map<String, String>): ByteArray = withContext(Dispatchers.IO) {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.instanceFollowRedirects = false
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.useCaches = false
            conn.requestMethod = "GET"
            for ((k, v) in headers) conn.setRequestProperty(k, v)
            if (conn.responseCode != 200) throw BreachCheckException(BreachCheckException.Kind.FAILED)
            if (conn.contentLengthLong > MAX_BYTES) throw BreachCheckException(BreachCheckException.Kind.FAILED)
            conn.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(16_384)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_BYTES) throw BreachCheckException(BreachCheckException.Kind.FAILED)
                }
                out.toByteArray()
            }
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        const val MAX_BYTES = 200_000
        private const val TIMEOUT_MS = 10_000
    }
}

class BreachScanResult(
    /** Login id -> times seen in breaches, for every login that was checked. */
    val counts: Map<String, Int>,
    /** Logins whose check failed (no result available). */
    val failed: Set<String>,
    val cancelled: Boolean,
) {
    val breached: Set<String> get() = counts.filterValues { it > 0 }.keys
}

/**
 * Explicit Have I Been Pwned range check (k-anonymity: only a 5-character SHA-1 prefix leaves the phone).
 * Results are kept by the caller in memory only.
 */
class BreachChecker(
    private val transport: BreachTransport,
    private val appVersion: String,
    private val strictOffline: () -> Boolean,
    private val enabled: () -> Boolean,
    private val pauseMillis: Long = 1_500,
) {
    private fun gate() {
        if (strictOffline()) throw BreachCheckException(BreachCheckException.Kind.STRICT_OFFLINE)
        if (!enabled()) throw BreachCheckException(BreachCheckException.Kind.DISABLED)
    }

    /** Times the password appears in breaches; 0 = not found. */
    suspend fun check(password: String): Int {
        gate()
        // SHA-1 is mandated by the HIBP range API, not used for security.
        val digest = MessageDigest.getInstance("SHA-1").digest(password.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02X".format(it) }
        val prefix = digest.substring(0, 5)
        val suffix = digest.substring(5)
        val data = try {
            transport.get(
                "https://api.pwnedpasswords.com/range/$prefix",
                mapOf("Add-Padding" to "true", "User-Agent" to "LocalGateKeys/$appVersion"),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw BreachCheckException(BreachCheckException.Kind.FAILED)
        }
        return count(data, suffix)
    }

    /** Checks every login, requesting identical passwords once, pausing between requests. */
    suspend fun scan(logins: List<HealthLogin>, progress: (Int, Int) -> Unit = { _, _ -> }): BreachScanResult {
        val counts = HashMap<String, Int>()
        val failed = HashSet<String>()
        var cancelled = false
        val groups = LinkedHashMap<String, MutableList<String>>()
        for (login in logins) if (login.password.isNotEmpty()) groups.getOrPut(login.password) { ArrayList() }.add(login.id)
        val total = groups.size
        progress(0, total)
        loop@ for ((index, entry) in groups.entries.withIndex()) {
            val (password, ids) = entry
            if (!currentCoroutineContext().isActive) { cancelled = true; break }
            if (index > 0 && pauseMillis > 0) {
                try { delay(pauseMillis) } catch (e: CancellationException) { cancelled = true; break }
            }
            val outcome: Result<Int> = try {
                Result.success(check(password))
            } catch (e: CancellationException) {
                cancelled = true; break
            } catch (e: Exception) {
                Result.failure(e)
            }
            // Cancelled mid-request: leave these logins "not checked", not failed.
            if (!currentCoroutineContext().isActive) { cancelled = true; break }
            val error = outcome.exceptionOrNull()
            when {
                error == null -> for (id in ids) counts[id] = outcome.getOrThrow()
                error is BreachCheckException &&
                    (error.kind == BreachCheckException.Kind.STRICT_OFFLINE || error.kind == BreachCheckException.Kind.DISABLED) -> {
                    cancelled = true
                    break@loop
                }
                else -> failed.addAll(ids)
            }
            progress(index + 1, total)
        }
        return BreachScanResult(counts, failed, cancelled)
    }

    companion object {
        const val MAX_BYTES = 200_000

        /** The count for [suffix] in a range response; throws FAILED when the body is not a valid response. */
        fun count(data: ByteArray, suffix: String): Int {
            if (data.size > MAX_BYTES) throw BreachCheckException(BreachCheckException.Kind.FAILED)
            val text = String(data, Charsets.ISO_8859_1)
            if (text.any { it.code > 127 }) throw BreachCheckException(BreachCheckException.Kind.FAILED)
            var count = 0
            var valid = 0
            for (raw in text.split('\n', '\r')) {
                val line = raw.trim(' ', '\t')
                if (line.isEmpty()) continue
                val parts = line.split(':')
                if (parts.size != 2 || parts[0].length != 35) continue
                if (!parts[0].all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) continue
                if (parts[1].isEmpty() || !parts[1].all { it in '0'..'9' }) continue
                valid++
                if (parts[0].uppercase() == suffix) count = maxOf(count, parts[1].toIntOrNull() ?: Int.MAX_VALUE)
            }
            if (valid == 0) throw BreachCheckException(BreachCheckException.Kind.FAILED)
            return count
        }
    }
}
