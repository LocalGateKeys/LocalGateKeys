package app.localgatekeys.android.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BreachCheckTest {
    private fun checker(transport: BreachTransport, strict: Boolean = false, enabled: Boolean = true) =
        BreachChecker(transport, "1.0", { strict }, { enabled }, pauseMillis = 0)

    private fun kind(block: () -> Unit): BreachCheckException.Kind {
        try { block() } catch (e: BreachCheckException) { return e.kind }
        fail("expected a BreachCheckException"); error("unreachable")
    }

    @Test fun only_the_five_character_prefix_is_sent_with_padding_and_a_user_agent() = runBlocking {
        val t = RecordingTransport { rangeBody("password", 3861493) }
        assertEquals(3861493, checker(t).check("password"))
        assertEquals("https://api.pwnedpasswords.com/range/" + sha1Prefix("password"), t.urls.single())
        assertEquals("5BAA6", sha1Prefix("password"))
        assertEquals("true", t.headers.single()["Add-Padding"])
        assertEquals("LocalGateKeys/1.0", t.headers.single()["User-Agent"])
        assertFalse(t.urls.single().contains("1E4C9B93F3F0")) // the suffix never leaves
    }

    @Test fun a_password_that_is_not_listed_counts_zero() = runBlocking {
        assertEquals(0, checker(RecordingTransport { rangeBody("some other one", 5) }).check("password"))
    }

    @Test fun nothing_is_sent_while_strict_offline_or_disabled() = runBlocking {
        val t = RecordingTransport()
        assertEquals(BreachCheckException.Kind.STRICT_OFFLINE, kind { runBlocking { checker(t, strict = true).check("password") } })
        assertEquals(BreachCheckException.Kind.DISABLED, kind { runBlocking { checker(t, enabled = false).check("password") } })
        assertEquals(0, t.requests)
    }

    @Test fun a_bad_body_or_a_transport_error_fails_and_a_big_body_is_refused() = runBlocking {
        for (body in listOf("".toByteArray(), "garbage\n".toByteArray(), "ZZZ:1\n".toByteArray(), ByteArray(BreachChecker.MAX_BYTES + 1) { 'A'.code.toByte() })) {
            assertEquals(BreachCheckException.Kind.FAILED, kind { runBlocking { checker(RecordingTransport { body }).check("password") } })
        }
        val boom = object : BreachTransport { override suspend fun get(url: String, headers: Map<String, String>): ByteArray = throw java.io.IOException("x") }
        assertEquals(BreachCheckException.Kind.FAILED, kind { runBlocking { checker(boom).check("password") } })
    }

    @Test fun identical_passwords_are_requested_once_and_empty_ones_never() = runBlocking {
        val t = RecordingTransport { rangeBody("password", 9) }
        val logins = listOf(
            HealthLogin("a", "a", "password", false, null), HealthLogin("b", "b", "password", false, null),
            HealthLogin("c", "c", "", false, null),
        )
        val result = checker(t).scan(logins)
        assertEquals(1, t.requests)
        assertEquals(mapOf("a" to 9, "b" to 9), result.counts)
        assertEquals(setOf("a", "b"), result.breached)
        assertTrue(result.failed.isEmpty()); assertFalse(result.cancelled)
    }

    @Test fun a_failed_request_marks_only_its_logins_and_a_refusal_cancels_the_scan() = runBlocking {
        var n = 0
        val flaky = RecordingTransport { if (n++ == 0) throw java.io.IOException("x") else rangeBody("two", 1) }
        val logins = listOf(HealthLogin("a", "a", "one", false, null), HealthLogin("b", "b", "two", false, null))
        val result = checker(flaky).scan(logins)
        assertEquals(setOf("a"), result.failed); assertEquals(mapOf("b" to 1), result.counts)

        val refused = checker(RecordingTransport(), strict = true).scan(logins)
        assertTrue(refused.cancelled); assertTrue(refused.counts.isEmpty()); assertTrue(refused.failed.isEmpty())
    }

    @Test fun a_response_line_for_the_suffix_takes_the_largest_count() {
        val suffix = "A".repeat(35)
        val body = ("A".repeat(35) + ":2\n" + "a".repeat(35) + ":7\n" + "B".repeat(35) + ":x\n").toByteArray()
        assertEquals(7, BreachChecker.count(body, suffix))
    }
}
