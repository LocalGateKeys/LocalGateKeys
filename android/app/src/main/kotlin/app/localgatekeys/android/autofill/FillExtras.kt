package app.localgatekeys.android.autofill

import android.content.Intent
import android.os.SystemClock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/** A [FillTarget] in an Intent's extras (our own unexported activities only; never a secret). */
object FillExtras {
    private const val KIND = "lgk.target.kind"
    private const val VALUE = "lgk.target.value"
    private const val BROWSER = "lgk.target.browser"
    private const val CERT = "lgk.target.cert"

    fun put(i: Intent, t: FillTarget): Intent = when (t) {
        is FillTarget.Web -> i.putExtra(KIND, "web").putExtra(VALUE, t.origin).putExtra(BROWSER, t.browser)
        is FillTarget.App -> i.putExtra(KIND, "app").putExtra(VALUE, t.packageName).putExtra(CERT, t.cert)
    }

    fun get(i: Intent): FillTarget? {
        val v = i.getStringExtra(VALUE) ?: return null
        return when (i.getStringExtra(KIND)) {
            "web" -> FillTarget.Web(v, i.getStringExtra(BROWSER) ?: "")
            "app" -> FillTarget.App(v, i.getStringExtra(CERT) ?: "")
            else -> null
        }
    }
}

/**
 * What the person typed, from `onSaveRequest` to the save sheet, kept in this process only: the Intent that opens the
 * sheet goes through the system and carries just a random token. Entries expire after five minutes and are taken once.
 */
object PendingSaves {
    class Pending(val target: FillTarget, val username: String, val password: String, val at: Long) {
        override fun toString(): String = "Pending(target=$target)"
    }

    private const val TTL_MS = 5 * 60_000L
    private val map = ConcurrentHashMap<String, Pending>()
    private val random = SecureRandom()

    fun put(target: FillTarget, username: String, password: String): String {
        val now = SystemClock.elapsedRealtime()
        map.entries.removeIf { now - it.value.at > TTL_MS }
        val token = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        map[token] = Pending(target, username, password, now)
        return token
    }

    fun take(token: String?): Pending? {
        token ?: return null
        val p = map.remove(token) ?: return null
        return if (SystemClock.elapsedRealtime() - p.at > TTL_MS) null else p
    }
}
