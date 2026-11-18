package app.localgatekeys.android.security

import app.localgatekeys.android.backup.BackupPasswordCheck
import app.localgatekeys.android.generator.TestWordlist
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.core.json.JsonValue.Obj
import java.security.MessageDigest

const val NOW = 1_800_000_000L

/** The desktop estimator's score, with the shipped word list installed as on the phone. */
val strength: (String) -> Int by lazy {
    TestWordlist.install()
    val estimator = BackupPasswordCheck.estimator
    ({ p: String -> estimator.estimate(p).score })
}

fun login(id: String, password: String, totp: Boolean = false, updated: Long = 1_790_000_000L, tags: List<String> = emptyList(), kind: String = "web"): Obj {
    val fields = mutableListOf(
        "id" to s(id), "kind" to s(kind), "label" to s("Site $id"), "username" to s("u"), "password" to s(password),
        "scope" to rec("origin" to s("https://$id.example.com")), "updated_at" to i(updated),
        "tags" to app.localgatekeys.android.vault.strs(*tags.toTypedArray()),
    )
    if (totp) fields += "totp" to rec("algorithm" to s("SHA1"), "digits" to i(6), "period" to i(30), "secret" to s("JBSWY3DPEHPK3PXP"))
    return Obj(fields.toMap())
}

/** The range-API body for a password: its own suffix with [count] plus a padded zero row. */
fun rangeBody(password: String, count: Int): ByteArray {
    val hex = MessageDigest.getInstance("SHA-1").digest(password.toByteArray()).joinToString("") { "%02X".format(it) }
    return ("0".repeat(35) + ":0\r\n" + hex.substring(5) + ":$count\r\n").toByteArray()
}

fun sha1Prefix(password: String): String =
    MessageDigest.getInstance("SHA-1").digest(password.toByteArray()).joinToString("") { "%02X".format(it) }.substring(0, 5)

/** Counts requests and records the URLs and headers; answers every password with [count] unless [body] is set. */
class RecordingTransport(private val answer: (String) -> ByteArray = { rangeBody("password", 3) }) : BreachTransport {
    val urls = java.util.concurrent.CopyOnWriteArrayList<String>()
    val headers = java.util.concurrent.CopyOnWriteArrayList<Map<String, String>>()
    val requests: Int get() = urls.size

    override suspend fun get(url: String, headers: Map<String, String>): ByteArray {
        urls.add(url)
        this.headers.add(headers)
        return answer(url)
    }
}
