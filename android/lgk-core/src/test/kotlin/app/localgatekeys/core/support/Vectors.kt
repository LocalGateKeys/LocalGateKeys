package app.localgatekeys.core.support

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import java.io.File

/** Locates the shared test vectors under `<repo>/tests/vectors`. Missing files fail the test, never skip it. */
object Vectors {
    val root: File = run {
        val repo = System.getProperty("lgk.repoRoot") ?: error("system property lgk.repoRoot is not set")
        File(repo, "tests/vectors").also { check(it.isDirectory) { "vectors directory missing: $it" } }
    }

    fun sync(rel: String): File = File(root, "sync/$rel").also { check(it.isFile) { "vector missing: $it" } }

    fun backup(rel: String): File = File(root, "backup/$rel").also { check(it.isFile) { "vector missing: $it" } }

    fun json(file: File): JsonValue = CanonicalJson.parse(file.readBytes())

    fun hex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun hexString(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
