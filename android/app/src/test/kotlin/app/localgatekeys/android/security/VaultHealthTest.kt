package app.localgatekeys.android.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The iPhone `VaultHealthTests`: the same cases, the same numbers. */
class VaultHealthTest {
    private val strong = "correct horse battery staple"
    private fun cache() = StrengthCache(strength)

    private fun login(id: String, password: String, totp: Boolean = true, daysOld: Double = 1.0) =
        HealthLogin(id, id, password, totp, NOW - (daysOld * 86_400).toLong())

    @Test fun score_and_bands() {
        val empty = VaultHealth.compute(emptyList(), emptySet(), NOW, cache())
        assertNull(empty.score); assertEquals(HealthBand.NONE, empty.band); assertEquals(0, empty.total)

        val good = VaultHealth.compute(listOf(login("a", strong), login("b", "Tr0ub4dor&3")), emptySet(), NOW, cache())
        assertEquals(100, good.score); assertEquals(HealthBand.GOOD, good.band)

        // a weak, b+c reused, d breached, e,f,g fine -> 3/7 = 42.857 -> 43 Poor
        val mixed = listOf(
            login("a", "password"), login("b", strong), login("c", strong), login("d", "Tr0ub4dor&3"),
            login("e", "Xq7!vR2#mL9pZ"), login("f", "Gh8\$kP3@wN6t"), login("g", "Yt5%bJ1^cV4s"),
        )
        val h = VaultHealth.compute(mixed, setOf("d", "zzz"), NOW, cache())
        assertEquals(setOf("a"), h.weak); assertEquals(setOf("b", "c"), h.reused); assertEquals(setOf("d"), h.breached)
        assertEquals(setOf("a", "b", "c", "d"), h.attention)
        assertEquals(43, h.score); assertEquals(HealthBand.POOR, h.band)

        val fair = VaultHealth.compute(listOf(login("a", "password"), login("b", strong)), emptySet(), NOW, cache())
        assertEquals(50, fair.score); assertEquals(HealthBand.FAIR, fair.band)
    }

    @Test fun reused_is_by_sha256_and_skips_empty_passwords() {
        val h = VaultHealth.compute(listOf(login("a", ""), login("b", ""), login("c", strong), login("d", "$strong ")), emptySet(), NOW, cache())
        assertEquals(emptySet<String>(), h.reused)
        assertTrue(h.weak.containsAll(setOf("a", "b")))
    }

    @Test fun old_is_not_in_the_score_and_an_unknown_date_is_never_old() {
        val h = VaultHealth.compute(
            listOf(login("a", strong, totp = false, daysOld = 400.0), login("b", "Tr0ub4dor&3"), HealthLogin("c", "c", "Tr0ub4dor&3x", true, null)),
            emptySet(), NOW, cache(),
        )
        // No site features: nothing is known to offer 2FA, so the 2FA category is empty (see VaultHealthSiteCasesTest).
        assertEquals(setOf("a"), h.old); assertEquals(emptySet<String>(), h.noTwoFactor)
        assertEquals(100, h.score)
    }

    @Test fun the_score_rounds_half_to_even_like_the_phone_and_the_desktop() {
        // 1 of 8 needs attention -> 87.5 -> 88 (even); 3 of 8 -> 62.5 -> 62 (even).
        fun score(attention: Int): Int? {
            val logins = (0 until 8).map { k -> login("l$k", if (k < attention) "password" else "Xq7!vR2#mL9pZ$k") }
            return VaultHealth.compute(logins, emptySet(), NOW, cache()).score
        }
        assertEquals(88, score(1)); assertEquals(62, score(3))
    }

    @Test fun the_cache_remembers_scores_by_digest_and_forgets_on_clear() {
        var calls = 0
        val cache = StrengthCache { calls++; 4 }
        val logins = (0 until 50).map { login("$it", strong) }
        VaultHealth.compute(logins, emptySet(), NOW, cache)
        VaultHealth.compute(logins, emptySet(), NOW, cache)
        assertEquals(1, calls)
        cache.removeAll()
        VaultHealth.compute(logins, emptySet(), NOW, cache)
        assertEquals(2, calls)
        assertEquals(50, VaultHealth.compute(logins, emptySet(), NOW, cache).reused.size)
    }

    @Test fun a_login_never_prints_its_password() {
        assertTrue(!login("a", strong).toString().contains("horse"))
    }
}
