package app.localgatekeys.android.unlock

import app.localgatekeys.android.unlock.OwnerGate.BiometricAnswer
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Audit A1: with the app password on, the owner check never accepts the phone's screen lock. */
class OwnerGateTest {
    private var passwordOn = true
    private var shortcut = false
    private var bio = BiometricAnswer.USE_PASSWORD
    private var unlocked = true
    private val deviceCalls = mutableListOf<String>()
    private var deviceAnswer = true
    private val typed = ArrayDeque<String?>()
    private val problems = mutableListOf<String?>()
    private val given = mutableListOf<ByteArray>()
    private val right = "correct horse"
    private var bioCalls = 0

    private class Wrong : Exception()

    private fun gate() = OwnerGate(
        passwordOn = { passwordOn },
        deviceCheck = { r -> deviceCalls += r; deviceAnswer },
        biometricShortcut = { shortcut },
        biometric = { bioCalls++; bio },
        askPassword = { _, problem -> problems += problem; typed.removeFirstOrNull()?.toByteArray()?.also { given += it } },
        verifyPassword = { p -> if (String(p) != right) throw Wrong() },
        stillUnlocked = { unlocked },
        problem = { e -> if (e is Wrong) "wrong" else null },
        wrongPassword = "wrong",
    )

    @Test fun password_off_keeps_the_screen_lock_check() = runBlocking {
        passwordOn = false
        assertTrue(gate().confirm("Export"))
        assertEquals(listOf("Export"), deviceCalls)
        deviceAnswer = false
        assertFalse(gate().confirm("Export"))
    }

    @Test fun password_on_never_asks_the_screen_lock() = runBlocking {
        typed += right
        assertTrue(gate().confirm("Export"))
        assertTrue(deviceCalls.isEmpty())
    }

    @Test fun cancelling_the_password_refuses() = runBlocking {
        typed += null
        assertFalse(gate().confirm("Export"))
        assertTrue(deviceCalls.isEmpty())
    }

    @Test fun a_wrong_password_asks_again_with_the_message_and_is_zeroed() = runBlocking {
        typed += "guess"; typed += ""; typed += right
        assertTrue(gate().confirm("Export"))
        assertEquals(listOf(null, "wrong", "wrong"), problems)
        assertTrue(given.all { b -> b.all { it == 0.toByte() } })
    }

    @Test fun the_fingerprint_shortcut_confirms_without_a_password() = runBlocking {
        shortcut = true; bio = BiometricAnswer.CONFIRMED
        assertTrue(gate().confirm("Export"))
        assertTrue(problems.isEmpty())
        assertTrue(deviceCalls.isEmpty())
    }

    @Test fun a_cancelled_fingerprint_refuses_and_a_failed_one_falls_back_to_the_password() = runBlocking {
        shortcut = true; bio = BiometricAnswer.CANCELLED
        assertFalse(gate().confirm("Export"))
        bio = BiometricAnswer.USE_PASSWORD
        typed += right
        assertTrue(gate().confirm("Export"))
        assertEquals(1, problems.size)
    }

    @Test fun no_shortcut_means_no_fingerprint_prompt() = runBlocking {
        typed += right
        assertTrue(gate().confirm("Export"))
        assertEquals(0, bioCalls)
    }

    @Test fun locked_vault_refuses() = runBlocking {
        unlocked = false
        typed += right
        assertFalse(gate().confirm("Export"))
    }
}
