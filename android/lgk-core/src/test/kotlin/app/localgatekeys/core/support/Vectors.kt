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

    /** Shared-collection vectors (sub-plan 07): `tests/vectors/share/collections/<rel>`. */
    fun shareCollections(rel: String): File =
        File(root, "share/collections/$rel").also { check(it.isFile) { "vector missing: $it" } }

    fun backup(rel: String): File = File(root, "backup/$rel").also { check(it.isFile) { "vector missing: $it" } }

    /** Any file under `tests/vectors`, e.g. `lookalike/cases.json`. */
    fun file(rel: String): File = File(root, rel).also { check(it.isFile) { "vector missing: $it" } }

    fun json(file: File): JsonValue = CanonicalJson.parse(file.readBytes())

    /**
     * Feature pack 2026-11-15 vectors, written by the Windows agent in parallel: the file under `tests/vectors`, or a
     * JUnit assumption failure (the test is reported as skipped) while it is not there yet.
     */
    fun optional(rel: String): File {
        val f = File(root, rel)
        org.junit.jupiter.api.Assumptions.assumeTrue(f.isFile, "vector not there yet: $rel")
        return f
    }

    fun hex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun hexString(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

/** JUnit 4 argument order (message first) over kotlin.test. */
fun <T> assertEq(message: String, expected: T, actual: T) = kotlin.test.assertEquals(expected, actual, message)

fun assertTr(message: String, actual: Boolean) = kotlin.test.assertTrue(actual, message)
