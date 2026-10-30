package app.localgatekeys.core.crypto

import app.localgatekeys.core.primitives.SystemRandomSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.test.Test

class Bip39Test {
    @Test fun desktop_vectors_round_trip() {
        val zero = ByteArray(32)
        val p = Bip39.phrase(zero)
        assertEquals((List(23) { "abandon" } + "art").joinToString(" "), p)
        assertContentEquals(zero, Bip39.entropy(p))
        val ff = ByteArray(32) { -1 }
        assertEquals((List(23) { "zoo" } + "vote").joinToString(" "), Bip39.phrase(ff))
        assertContentEquals(ff, Bip39.entropy("  ZOO zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo\nzoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo Vote "))
    }

    @Test fun random_round_trip() {
        repeat(20) {
            val e = SystemRandomSource().bytes(32)
            assertContentEquals(e, Bip39.entropy(Bip39.phrase(e)))
        }
    }

    @Test fun bad_checksum_unknown_word_and_count_are_refused() {
        fun refused(s: String) = try { Bip39.entropy(s); fail("accepted: $s") } catch (e: RecoveryPhraseException) {}
        refused(List(24) { "abandon" }.joinToString(" "))
        refused((List(23) { "abandon" } + "notaword").joinToString(" "))
        refused(List(12) { "abandon" }.joinToString(" "))
    }
}

class AppPasswordWrapTest {
    private val random = SystemRandomSource()
    /** Small cost for speed; one test runs the desktop parameters. */
    private val cheap = AppPasswordParams(memoryKiB = 8192, iterations = 1, parallelism = 1)
    private val pw = AppPasswordRecord.passwordBytes("correct horse battery")

    @Test fun wrap_then_unwrap_with_password_and_phrase() {
        val local = random.bytes(32)
        val c = AppPasswordRecord.create(local, pw, random, cheap)
        val back = AppPasswordRecord.decode(c.record.encode())
        assertContentEquals(local, back.unwrapWithPassword(pw))
        assertContentEquals(local, back.unwrapWithPhrase(c.phrase))
        assertEquals(AppPasswordRecord.SIZE, c.record.encode().size)
        assertTrue(!c.record.toString().contains(c.phrase.split(" ")[0] + " "))
    }

    @Test fun desktop_parameters_are_the_default_and_work() {
        assertEquals(AppPasswordParams(65536, 3, 4), AppPasswordParams.DESKTOP)
        val local = random.bytes(32)
        val c = AppPasswordRecord.create(local, pw, random)
        assertEquals(AppPasswordParams.DESKTOP, AppPasswordRecord.decode(c.record.encode()).params)
        assertContentEquals(local, c.record.unwrapWithPassword(pw))
    }

    @Test fun wrong_password_and_wrong_phrase_fail() {
        val c = AppPasswordRecord.create(random.bytes(32), pw, random, cheap)
        try { c.record.unwrapWithPassword(AppPasswordRecord.passwordBytes("correct horse batterY")); fail() } catch (e: AppPasswordException) {
            assertEquals(AppPasswordException.Kind.WRONG_PASSWORD, e.kind)
        }
        val other = AppPasswordRecord.create(random.bytes(32), pw, random, cheap).phrase
        try { c.record.unwrapWithPhrase(other); fail() } catch (e: AppPasswordException) {
            assertEquals(AppPasswordException.Kind.WRONG_PHRASE, e.kind)
        }
    }

    @Test fun change_password_keeps_the_recovery_wrapper() {
        val local = random.bytes(32)
        val c = AppPasswordRecord.create(local, pw, random, cheap)
        val newPw = AppPasswordRecord.passwordBytes("a brand new pass phrase")
        val changed = c.record.withNewPassword(local, newPw, random)
        assertContentEquals(local, changed.unwrapWithPassword(newPw))
        assertContentEquals(local, changed.unwrapWithPhrase(c.phrase))
        try { changed.unwrapWithPassword(pw); fail() } catch (e: AppPasswordException) {}
        assertContentEquals(c.record.encode().copyOfRange(AppPasswordRecord.SIZE - 76, AppPasswordRecord.SIZE), changed.encode().copyOfRange(AppPasswordRecord.SIZE - 76, AppPasswordRecord.SIZE))
    }

    @Test fun tampered_header_and_bad_sizes_are_refused() {
        val c = AppPasswordRecord.create(random.bytes(32), pw, random, cheap)
        val bytes = c.record.encode()
        // Raising the cost in the header breaks the AAD, so it cannot be used to change parameters silently.
        val t = bytes.copyOf().also { it[11] = 2 }
        try { AppPasswordRecord.decode(t).unwrapWithPassword(pw); fail() } catch (e: AppPasswordException) {}
        try { AppPasswordRecord.decode(bytes.copyOf(100)); fail() } catch (e: AppPasswordException) {
            assertEquals(AppPasswordException.Kind.MALFORMED, e.kind)
        }
        val badParams = bytes.copyOf().also { it[11] = 0 }
        try { AppPasswordRecord.decode(badParams); fail() } catch (e: AppPasswordException) {
            assertEquals(AppPasswordException.Kind.MALFORMED, e.kind)
        }
    }

    @Test fun two_records_for_the_same_key_differ() {
        val local = random.bytes(32)
        assertNotEquals(
            AppPasswordRecord.create(local, pw, random, cheap).record.encode().toList(),
            AppPasswordRecord.create(local, pw, random, cheap).record.encode().toList(),
        )
    }

    @Test fun wrong_try_delay() {
        assertEquals(0, AppPasswordDelay.seconds(4))
        assertEquals(30, AppPasswordDelay.seconds(5))
        assertEquals(60, AppPasswordDelay.seconds(6))
        assertEquals(900, AppPasswordDelay.seconds(50))
        assertEquals(20, AppPasswordDelay.remaining(5, lastFailureAt = 100, now = 110))
        assertEquals(0, AppPasswordDelay.remaining(5, lastFailureAt = 100, now = 200))
        assertEquals(30, AppPasswordDelay.remaining(5, lastFailureAt = 100, now = 50))
        // Same boot: a wall clock moved a day forward does not count, the monotonic clock does.
        assertEquals(30, AppPasswordDelay.remaining(5, 100, now = 100 + 86_400, lastFailureElapsed = 500, elapsed = 500, sameBoot = true))
        assertEquals(10, AppPasswordDelay.remaining(5, 100, now = 100 + 86_400, lastFailureElapsed = 500, elapsed = 520, sameBoot = true))
        assertEquals(0, AppPasswordDelay.remaining(5, 100, now = 100, lastFailureElapsed = 500, elapsed = 530, sameBoot = true))
        // After a restart (or without a stamp, or a monotonic clock that went back) the wall clock decides as before.
        assertEquals(20, AppPasswordDelay.remaining(5, 100, now = 110, lastFailureElapsed = 500, elapsed = 3, sameBoot = false))
        assertEquals(20, AppPasswordDelay.remaining(5, 100, now = 110, lastFailureElapsed = -1, elapsed = 3, sameBoot = true))
        assertEquals(20, AppPasswordDelay.remaining(5, 100, now = 110, lastFailureElapsed = 500, elapsed = 3, sameBoot = true))
        assertEquals(30, AppPasswordDelay.remaining(5, 100, now = 50, lastFailureElapsed = 500, elapsed = 3, sameBoot = false))
    }
}
