package app.localgatekeys.android.duress

import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** Audit 2026-11-10 (as the iPhone): the duress hold also counts on the monotonic clock, so the date cannot shorten it. */
class DuressHoldClockTest {
    private class Boot(var elapsed0: Long, var boot0: Long) : BootClock {
        override val elapsed: Long get() = elapsed0
        override val boot: Long get() = boot0
    }

    private lateinit var base: File
    private lateinit var clock: TestClock
    private lateinit var boot: Boot
    private lateinit var duress: DuressVault
    private val hold = DuressVault.DEFAULT_HOURS * 3600L // no config file: trip() uses the default hours

    @Before fun setUp() {
        base = tempDir("duress-hold")
        clock = TestClock(1_800_000_000)
        boot = Boot(1000, 7)
        duress = DuressVault(DuressFiles.under(base), SystemRandomSource(), clock, bootClock = boot)
    }

    private fun trip(): Long = duress.trip(ByteArray(32))

    @Test fun moving_the_date_forward_does_not_end_the_hold() {
        val until = trip()
        assertEquals(clock.now + hold, until)
        clock.now += 10 * hold // date set far forward, no real time passed
        assertEquals(clock.now + hold, duress.heldUntil())
        boot.elapsed0 += hold - 60
        assertEquals(clock.now + 60, duress.heldUntil())
        boot.elapsed0 += 60
        assertNull(duress.heldUntil())
        assertEquals(1_800_000_000L, duress.release())
    }

    @Test fun moving_the_date_back_does_not_end_the_hold() {
        val until = trip()
        boot.elapsed0 += hold + 1 // the monotonic count is done...
        clock.now -= 3600 // ...but the date was set back: the wall clock still has to pass until
        assertEquals(until, duress.heldUntil())
    }

    @Test fun a_restart_counts_only_the_time_since_it() {
        trip()
        clock.now += 2 * hold
        boot.boot0 = 8
        boot.elapsed0 = 50 // another boot, 50 s since it
        assertEquals(clock.now + hold - 50, duress.heldUntil())
        // Unknown boot count: a clock below the anchor is a restart.
        boot.boot0 = -1
        boot.elapsed0 = 10
        assertEquals(clock.now + hold - 10, duress.heldUntil())
    }

    @Test fun remaining_rules() {
        assertEquals(3600, DuressVault.monotonicRemaining(7200, 100, 1, 3700, 1))
        assertEquals(-1800, DuressVault.monotonicRemaining(7200, 5000, 1, 9000, 2))
        assertEquals(7150, DuressVault.monotonicRemaining(7200, 5000, null, 50, -1))
        assertEquals(6200, DuressVault.monotonicRemaining(7200, 5000, 1, 6000, -1))
        assertEquals(7200, DuressVault.monotonicRemaining(7200, 5000, 1, -1, -1))
    }

    @Test fun hold_without_an_anchor_uses_the_wall_clock() {
        val o = mapOf("version" to JsonValue.Int(1), "since" to JsonValue.Int(clock.now), "until" to JsonValue.Int(clock.now + 3600))
        DuressFiles.under(base).hold.writeBytes(CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8))
        assertEquals(clock.now + 3600, duress.heldUntil())
        clock.now += 3601
        assertNull(duress.heldUntil())
    }

    @Test fun no_monotonic_clock_writes_no_anchor() {
        duress = DuressVault(DuressFiles.under(base), SystemRandomSource(), clock)
        val until = trip()
        clock.now = until
        assertNull(duress.heldUntil())
    }
}
