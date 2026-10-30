package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import androidx.biometric.BiometricPrompt
import app.localgatekeys.android.detail.FakeClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.AutoLockDelay
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.settings.IdleLock
import app.localgatekeys.android.settings.FlakyPrefs
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.settings.SharedPrefsStore
import app.localgatekeys.android.unlock.AppLockModel.State
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.VaultKeyException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Port of ios/LocalGateKeysTests/AppLockModelTests.swift (scene phases mapped to the Android lifecycle). */
class AppLockModelTest {
    private lateinit var clock: TestClock
    private lateinit var scheduler: ManualScheduler
    private lateinit var unlocker: FakeUnlocker
    private lateinit var defaults: MemoryStore
    private lateinit var settings: AppSettings
    private lateinit var eraser: FakeEraser
    private lateinit var sink: FakeClipboardSink
    private lateinit var clipScheduler: ManualScheduler
    private lateinit var clipboard: SecretClipboard

    @Before fun setUp() {
        clock = TestClock(1_790_000_000)
        scheduler = ManualScheduler(clock)
        unlocker = FakeUnlocker()
        defaults = MemoryStore()
        settings = AppSettings(defaults)
        eraser = FakeEraser()
        sink = FakeClipboardSink()
        clipScheduler = ManualScheduler(clock)
        clipboard = SecretClipboard(sink, settings, clipScheduler, clock).also { it.focusChanged(true) }
    }

    private fun makeModel() = AppLockModel(unlocker, clock, scheduler, settings, clipboard, eraser, t = EnglishTxt())

    private fun unlocked(): AppLockModel = runBlocking {
        val m = makeModel()
        m.unlock()
        assertEquals(State.UNLOCKED, m.state.value)
        m
    }

    private fun AppLockModel.st() = state.value

    @Test fun starts_locked_and_unlocks_with_device_auth() = runBlocking {
        val m = makeModel()
        assertEquals(State.LOCKED, m.st()); assertNull(m.store)
        m.unlock()
        assertEquals(State.UNLOCKED, m.st()); assertNotNull(m.store); assertNotNull(m.vault.value)
        assertEquals(1, unlocker.unlockCalls)
    }

    @Test fun unlock_during_erase_returns_early() = runBlocking {
        val m = unlocked()
        val opens = unlocker.unlockCalls
        m.eraseAndLock { m.unlock() }
        assertEquals("no second erase", 1, eraser.calls)
        assertEquals("no vault opened", opens, unlocker.unlockCalls)
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun failed_auth_stays_locked() = runBlocking {
        unlocker.succeed = false
        val m = makeModel(); m.unlock()
        assertEquals(State.LOCKED, m.st()); assertNull(m.store); assertNotNull(m.errorMessage.value)
    }

    @Test fun default_background_delay_is_immediately() {
        assertEquals(AutoLockDelay.IMMEDIATELY, settings.autoLockDelay)
    }

    @Test fun background_locks_immediately_by_default() {
        val m = unlocked()
        m.didEnterBackground()
        assertEquals(State.LOCKED, m.st()); assertNull(m.store); assertEquals(1, unlocker.lockCalls)
    }

    @Test fun background_delay_locks_only_after_the_delay() {
        settings.autoLockDelay = AutoLockDelay.ONE_MINUTE
        val m = unlocked()
        m.didEnterBackground(); assertEquals(State.UNLOCKED, m.st())
        clock.now += 59; m.willEnterForeground(); assertEquals(State.UNLOCKED, m.st())
        m.didEnterBackground(); clock.now += 60; m.willEnterForeground()
        assertEquals(State.LOCKED, m.st())
    }

    // Ruling 21 (final): the system folder picker is another app's screen and stops this app. That one trip does not
    // count for the "Immediately" auto-lock; it is capped at 120 s (elapsed time), checked when the pick comes back and
    // on return, and a screen-off during the trip locks.

    /** The screen-off seam: [fire] is the screen turning off; [watching] while the model listens. */
    private class FakeScreenOff : ScreenOffWatching {
        var onOff: (() -> Unit)? = null
        var starts = 0
        val watching get() = onOff != null
        override fun start(onScreenOff: () -> Unit) { starts++; onOff = onScreenOff }
        override fun stop() { onOff = null }
        fun fire() = onOff?.invoke()
    }

    private val screenOff = FakeScreenOff()

    private fun pickerModel() = AppLockModel(unlocker, clock, scheduler, settings, clipboard, eraser, screenOff = screenOff, t = EnglishTxt())

    private fun pickerUnlocked(): AppLockModel = runBlocking {
        val m = pickerModel()
        m.sceneBecameActive()
        assertEquals(State.UNLOCKED, m.state.value)
        m
    }

    @Test fun system_picker_trip_does_not_lock() = runBlocking {
        val m = pickerUnlocked()
        m.willOpenSystemScreen()
        m.didEnterBackground()
        assertEquals(State.UNLOCKED, m.st())
        clock.now += 20
        assertTrue(m.systemScreenClosed()) // the pick is used
        m.sceneBecameActive() // back from the picker: no new prompt
        assertEquals(State.UNLOCKED, m.st()); assertEquals(1, unlocker.unlockCalls)
        // Single use: the next trip to the background locks as usual.
        m.didEnterBackground()
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun system_picker_left_open_locks_at_the_cap() {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        scheduler.advance(119); assertEquals(State.UNLOCKED, m.st())
        scheduler.advance(1); assertEquals(State.LOCKED, m.st())
        assertFalse(screenOff.watching)
    }

    /** The real return order: the result arrives (onStart -> result) before the scene is active again. */
    @Test fun pick_returned_after_the_cap_is_dropped_and_the_vault_locks_and_prompts() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now += 121 // the process slept: no timer fired
        assertFalse(m.systemScreenClosed()) // the pick must not be used
        assertEquals(State.LOCKED, m.st())
        m.sceneBecameActive()
        assertEquals(1, unlocker.lockCalls)
        assertEquals(2, unlocker.unlockCalls) // prompted again
    }

    @Test fun pick_returned_within_the_cap_keeps_the_vault() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now += 60
        assertTrue(m.systemScreenClosed())
        m.sceneBecameActive()
        assertEquals(State.UNLOCKED, m.st()); assertEquals(1, unlocker.unlockCalls); assertEquals(0, unlocker.lockCalls)
    }

    @Test fun return_after_the_cap_without_a_result_locks_and_prompts() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now += 121
        m.sceneBecameActive()
        assertEquals(2, unlocker.unlockCalls)
        assertEquals(1, unlocker.lockCalls)
    }

    @Test fun cap_is_measured_on_elapsed_time_not_the_wall_clock() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        var elapsed = 5_000_000L
        val m = AppLockModel(unlocker, clock, scheduler, settings, clipboard, eraser, screenOff = screenOff, elapsedMillis = { elapsed }, t = EnglishTxt())
        m.sceneBecameActive()
        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now -= 3600 // the wall clock was set back an hour
        elapsed += 121_000
        assertFalse(m.systemScreenClosed())
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun screen_off_during_the_trip_locks() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        assertFalse(screenOff.watching)
        m.willOpenSystemScreen()
        assertTrue(screenOff.watching) // listening only while the allowance lasts
        m.didEnterBackground()
        screenOff.fire()
        assertEquals(State.LOCKED, m.st())
        assertFalse(screenOff.watching)
        assertFalse(m.systemScreenClosed())
        m.sceneBecameActive()
        assertEquals(2, unlocker.unlockCalls)
    }

    @Test fun screen_watch_ends_with_the_allowance() {
        val m = pickerUnlocked()
        m.willOpenSystemScreen()
        assertTrue(m.systemScreenClosed())
        assertFalse(screenOff.watching)
        assertEquals(0, scheduler.timers.count { !it.cancelled && it.due == clock.now + 120 })
        screenOff.fire() // nothing listens any more
        assertEquals(State.UNLOCKED, m.st())
    }

    @Test fun lock_ends_the_allowance() {
        settings.idleLock = IdleLock.NEVER
        val m = pickerUnlocked()
        m.willOpenSystemScreen()
        m.lock()
        assertFalse(screenOff.watching)
        assertEquals(0, scheduler.pending)
        assertFalse(m.systemScreenClosed())
    }

    @Test fun idle_limit_still_applies_during_the_allowance() {
        settings.idleLock = IdleLock.ONE_MINUTE
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        scheduler.advance(60)
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun a_non_immediate_delay_still_counts_during_a_trip() = runBlocking {
        settings.idleLock = IdleLock.NEVER
        settings.autoLockDelay = AutoLockDelay.ONE_MINUTE
        val m = pickerUnlocked()
        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now += 30
        assertTrue(m.systemScreenClosed())
        m.sceneBecameActive(); assertEquals(State.UNLOCKED, m.st())

        m.willOpenSystemScreen(); m.didEnterBackground()
        clock.now += 61 // past the one-minute delay, within the 120 s cap
        assertFalse(m.systemScreenClosed())
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun system_picker_allowance_needs_an_unlocked_vault() {
        val m = pickerModel()
        m.willOpenSystemScreen()
        assertEquals(0, scheduler.pending)
        assertFalse(screenOff.watching)
        assertFalse(m.systemScreenClosed())
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun idle_locks_after_five_minutes() {
        val m = unlocked()
        scheduler.advance(299); assertEquals(State.UNLOCKED, m.st())
        scheduler.advance(1); assertEquals(State.LOCKED, m.st())
    }

    @Test fun activity_restarts_the_idle_timer() {
        val m = unlocked()
        scheduler.advance(200); m.noteActivity()
        scheduler.advance(299); assertEquals(State.UNLOCKED, m.st())
        scheduler.advance(1); assertEquals(State.LOCKED, m.st())
    }

    @Test fun idle_time_spent_in_background_counts_on_return() {
        settings.autoLockDelay = AutoLockDelay.FIFTEEN_MINUTES
        val m = unlocked()
        m.didEnterBackground(); clock.now += 301 // stopped: no timer fires
        m.willEnterForeground()
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun lock_cancels_the_idle_timer() {
        val m = unlocked()
        assertEquals(1, scheduler.pending)
        m.lock()
        assertEquals(0, scheduler.pending); assertEquals(State.LOCKED, m.st())
    }

    @Test fun activity_while_locked_does_nothing() {
        val m = makeModel(); m.noteActivity()
        assertEquals(0, scheduler.pending)
    }

    @Test fun lock_during_in_flight_unlock_wins() = runBlocking {
        val m = makeModel()
        unlocker.duringUnlock = { m.lock() }
        m.unlock()
        assertEquals(State.LOCKED, m.st()); assertNull(m.store); assertEquals(0, scheduler.pending)
        assertEquals("the late vault is shut, and only it", unlocker.opened, unlocker.discarded)
    }

    @Test fun lock_drops_the_store_holding_decoded_records() {
        val m = unlocked()
        m.lock()
        assertNull(m.store); assertNull(m.vault.value)
    }

    @Test fun lock_clears_our_clipboard_copy() {
        val m = unlocked()
        clipboard.copy("s3cret")
        m.lock()
        assertNull(sink.text)
    }

    @Test fun background_lock_keeps_the_copy_for_pasting_elsewhere() {
        val m = unlocked()
        assertEquals(AutoLockDelay.IMMEDIATELY, settings.autoLockDelay)
        clipboard.copy("123456")
        m.didEnterBackground()
        assertEquals(State.LOCKED, m.st())
        assertEquals("123456", sink.text)
    }

    @Test fun delayed_background_lock_keeps_the_copy() {
        settings.autoLockDelay = AutoLockDelay.ONE_MINUTE
        val m = unlocked()
        clipboard.copy("123456")
        m.didEnterBackground(); clock.now += 60; m.willEnterForeground()
        assertEquals(State.LOCKED, m.st())
        assertEquals("123456", sink.text)
    }

    @Test fun lock_leaves_a_later_foreign_copy_alone() {
        val m = unlocked()
        clipboard.copy("s3cret")
        sink.foreignCopy("user text")
        m.lock()
        assertEquals("user text", sink.text)
    }

    @Test fun test_clipboard_expiry_uses_the_setting() {
        settings.clipboardExpiry = ClipboardExpiry.THIRTY_SECONDS
        val s1 = ManualScheduler(clock)
        SecretClipboard(sink, settings, s1, clock).also { it.focusChanged(true) }.copy("x")
        assertEquals(clock.now + 30, s1.timers.single().due)
        settings.clipboardExpiry = ClipboardExpiry.FIVE_MINUTES
        val s2 = ManualScheduler(clock)
        SecretClipboard(sink, settings, s2, clock).also { it.focusChanged(true) }.copy("y")
        assertEquals(clock.now + 300, s2.timers.single().due)
        s2.advance(299); assertEquals("y", sink.text)
        s2.advance(1); assertNull(sink.text)
    }

    @Test fun idle_timeout_follows_the_setting() {
        settings.idleLock = IdleLock.ONE_MINUTE
        val m = unlocked()
        scheduler.advance(59); assertEquals(State.UNLOCKED, m.st())
        scheduler.advance(1); assertEquals(State.LOCKED, m.st())
    }

    @Test fun idle_never_schedules_no_timer_and_foreground_keeps_unlocked() {
        settings.idleLock = IdleLock.NEVER; settings.autoLockDelay = AutoLockDelay.ONE_HOUR
        val m = unlocked()
        assertEquals(0, scheduler.pending)
        scheduler.advance(100_000); assertEquals(State.UNLOCKED, m.st())
        m.didEnterBackground(); clock.now += 3599; m.willEnterForeground()
        assertEquals(State.UNLOCKED, m.st())
    }

    @Test fun one_hour_background_delay_locks_after_an_hour() {
        settings.autoLockDelay = AutoLockDelay.ONE_HOUR; settings.idleLock = IdleLock.NEVER
        val m = unlocked()
        m.didEnterBackground(); clock.now += 3600; m.willEnterForeground()
        assertEquals(State.LOCKED, m.st())
    }

    @Test fun changing_the_idle_setting_takes_effect_on_next_activity() {
        val m = unlocked()
        settings.idleLock = IdleLock.FIFTEEN_MINUTES
        m.noteActivity()
        scheduler.advance(300); assertEquals(State.UNLOCKED, m.st())
        scheduler.advance(600); assertEquals(State.LOCKED, m.st())
    }

    @Test fun erase_locks_first_even_when_it_fails_and_unlock_retries_it() = runBlocking {
        val m = unlocked()
        eraser.failuresLeft = 2
        var stateDuringWait: State? = null
        m.eraseAndLock {
            stateDuringWait = m.st()
            assertTrue("set before the erase", settings.erasePending)
        }
        assertEquals("locked before anything else runs", State.LOCKED, stateDuringWait)
        assertEquals(State.LOCKED, m.st()); assertNull(m.store)
        assertEquals(VaultEraseFailure(listOf("local-key")).text(EnglishTxt()), m.errorMessage.value)
        m.unlock() // the retry fails again: stays locked, no unlock attempted
        assertEquals(State.LOCKED, m.st()); assertEquals(2, eraser.calls); assertEquals(1, unlocker.unlockCalls)
        m.unlock() // the retry succeeds, then the unlock runs (a first run)
        assertEquals(3, eraser.calls); assertEquals(State.UNLOCKED, m.st()); assertNull(m.errorMessage.value)
    }

    @Test fun successful_erase_locks_with_no_message() = runBlocking {
        val m = unlocked()
        m.eraseAndLock()
        assertEquals(State.LOCKED, m.st()); assertNull(m.errorMessage.value); assertFalse(settings.erasePending)
    }

    @Test fun pending_erase_survives_a_relaunch_and_unlock_retries_it() = runBlocking {
        val m = unlocked()
        eraser.failuresLeft = 1
        m.eraseAndLock()
        assertTrue(settings.erasePending)
        // Relaunch: a new model over the same preferences.
        val relaunched = AppLockModel(unlocker, clock, scheduler, AppSettings(defaults), clipboard, eraser, t = EnglishTxt())
        relaunched.unlock()
        assertEquals("retried before unlocking", 2, eraser.calls)
        assertFalse(settings.erasePending)
        assertEquals(State.UNLOCKED, relaunched.st())
    }

    @Test fun crash_mid_erase_leaves_the_flag_set() = runBlocking {
        settings.erasePending = true // what a crash during erase() leaves behind
        val m = makeModel()
        eraser.failuresLeft = 1
        m.unlock()
        assertEquals(State.LOCKED, m.st()); assertEquals(0, unlocker.unlockCalls); assertTrue(settings.erasePending)
    }

    @Test fun healthy_vault_is_never_erased() = runBlocking {
        val m = unlocked(); m.lock()
        m.unlock()
        assertEquals(0, eraser.calls); assertEquals(State.UNLOCKED, m.st())
    }

    // Lifecycle: ON_START -> sceneBecameActive, ON_STOP -> didEnterBackground. The prompt's own dialog pauses
    // the activity (ON_PAUSE / ON_RESUME) but never starts it again, so it cannot re-prompt.

    @Test fun cancelled_prompt_is_not_reprompted_when_the_activity_starts_again() = runBlocking {
        unlocker.succeed = false
        val m = makeModel()
        m.sceneBecameActive() // launch: prompts once
        assertEquals(1, unlocker.unlockCalls)
        m.sceneBecameActive() // no trip to the background: no new prompt; the error stays visible
        assertEquals(1, unlocker.unlockCalls)
        assertEquals(State.LOCKED, m.st()); assertNotNull(m.errorMessage.value)
    }

    @Test fun return_from_background_prompts_again() = runBlocking {
        unlocker.succeed = false
        val m = makeModel()
        m.sceneBecameActive()
        m.didEnterBackground()
        m.sceneBecameActive()
        assertEquals(2, unlocker.unlockCalls)
        m.sceneBecameActive() // no third prompt
        assertEquals(2, unlocker.unlockCalls)
    }

    @Test fun background_lock_then_return_prompts_and_unlocks() = runBlocking {
        val m = makeModel()
        m.sceneBecameActive(); assertEquals(State.UNLOCKED, m.st())
        m.didEnterBackground(); assertEquals(State.LOCKED, m.st()) // immediately, by default
        m.sceneBecameActive()
        assertEquals(State.UNLOCKED, m.st()); assertEquals(2, unlocker.unlockCalls)
    }

    @Test fun manual_unlock_still_works_after_a_cancel() = runBlocking {
        unlocker.succeed = false; unlocker.error = AuthenticationException(BiometricPrompt.ERROR_USER_CANCELED)
        val m = makeModel()
        m.sceneBecameActive()
        unlocker.succeed = true
        m.unlock()
        assertEquals(State.UNLOCKED, m.st()); assertEquals(2, unlocker.unlockCalls)
    }

    /** Below API 30 the screen-lock screen is its own activity and stops ours while the unlock is in flight. */
    @Test fun background_during_an_unlock_does_not_reprompt_on_return() = runBlocking {
        unlocker.error = AuthenticationException(BiometricPrompt.ERROR_USER_CANCELED)
        val m = AppLockModel(unlocker, clock, scheduler, settings, clipboard, eraser, credentialScreenStopsApp = true, t = EnglishTxt())
        unlocker.duringUnlock = { m.didEnterBackground(); unlocker.succeed = false }
        m.sceneBecameActive() // launch: prompts; the credential screen stops the activity, then the person cancels
        unlocker.duringUnlock = null
        m.sceneBecameActive() // the activity starts again
        assertEquals("no prompt loop after a cancel", 1, unlocker.unlockCalls)
        assertEquals(State.LOCKED, m.st()); assertNull(m.errorMessage.value)
    }

    /** API 30+: the prompt is a system dialog, so a stop during it is a real trip and the iPhone rule applies. */
    @Test fun api30_background_during_an_unlock_prompts_again_on_return() = runBlocking {
        unlocker.error = AuthenticationException(BiometricPrompt.ERROR_USER_CANCELED)
        val m = makeModel() // credentialScreenStopsApp = false
        unlocker.duringUnlock = { m.didEnterBackground(); unlocker.succeed = false }
        m.sceneBecameActive()
        unlocker.duringUnlock = null
        unlocker.succeed = true
        m.sceneBecameActive()
        assertEquals(2, unlocker.unlockCalls)
        assertEquals(State.UNLOCKED, m.st())
    }

    /** A late unlock (lock won) shuts only its own vault: a newer unlock's prompt and vault are left alone. */
    @Test fun a_late_unlock_does_not_touch_a_newer_unlock() = runBlocking {
        val m = makeModel()
        val gateA = CompletableDeferred<Unit>()
        val gateB = CompletableDeferred<Unit>()
        unlocker.gates.addAll(listOf(gateA, gateB))
        val a = launch(start = CoroutineStart.UNDISPATCHED) { m.unlock() }
        m.lock() // the app locked while A was in flight
        assertEquals(1, unlocker.lockCalls)
        val b = launch(start = CoroutineStart.UNDISPATCHED) { m.unlock() } // the person taps Unlock again
        assertEquals(State.UNLOCKING, m.st())
        gateA.complete(Unit); a.join()
        assertEquals("only A's vault is shut", listOf(unlocker.opened[0]), unlocker.discarded)
        assertEquals("B's prompt is not dismissed", 1, unlocker.lockCalls)
        assertEquals(State.UNLOCKING, m.st())
        gateB.complete(Unit); b.join()
        assertEquals(State.UNLOCKED, m.st())
        assertSame(unlocker.opened[1], m.vault.value)
        assertEquals(1, unlocker.discarded.size)
    }

    /** The erase flag must be on disk before anything is deleted: a failed durable write erases nothing. */
    @Test fun erase_flag_that_cannot_be_saved_erases_nothing() = runBlocking {
        val prefs = FlakyPrefs() // commit() updates memory, then the disk write fails
        val s = AppSettings(SharedPrefsStore(prefs))
        val m = AppLockModel(unlocker, clock, scheduler, s, clipboard, eraser, t = EnglishTxt())
        m.unlock()
        prefs.failCommit = { true }
        m.eraseAndLock()
        assertEquals(0, eraser.calls)
        assertEquals(State.LOCKED, m.st())
        assertEquals(EnglishTxt().s(AppLockModel.ERASE_NOT_STARTED_MESSAGE), m.errorMessage.value)
        assertFalse("rolled back in memory", s.erasePending)
        assertFalse("not on disk", prefs.disk.containsKey(AppSettings.Key.ERASE_PENDING))
        prefs.failCommit = { false }
        m.unlock()
        assertEquals("no erase pending: the next unlock opens the vault", State.UNLOCKED, m.st())
        assertEquals(0, eraser.calls)
    }

    /** Clearing the flag after a successful erase failed: treated as a failed erase and retried before unlocking. */
    @Test fun erase_whose_done_flag_cannot_be_saved_is_retried() = runBlocking {
        val prefs = FlakyPrefs()
        val s = AppSettings(SharedPrefsStore(prefs))
        val m = AppLockModel(unlocker, clock, scheduler, s, clipboard, eraser, t = EnglishTxt())
        m.unlock()
        prefs.failCommit = { changes -> changes[AppSettings.Key.ERASE_PENDING] == false }
        m.eraseAndLock()
        assertTrue(m.eraseFailed); assertTrue(m.offersStartFresh.value)
        assertEquals(EnglishTxt().s(AppLockModel.ERASE_FAILED_MESSAGE), m.errorMessage.value)
        assertTrue("still set in memory and on disk", s.erasePending && prefs.disk[AppSettings.Key.ERASE_PENDING] == true)
        val opens = unlocker.unlockCalls
        prefs.failCommit = { false }
        m.unlock()
        assertEquals("erased again first", 2, eraser.calls)
        assertFalse(s.erasePending)
        assertEquals(opens + 1, unlocker.unlockCalls)
        assertEquals(State.UNLOCKED, m.st())
    }

    /** Start fresh for a vault without key whose erase flag cannot be saved: nothing ran, so it stays offered. */
    @Test fun start_fresh_with_an_unsaved_flag_keeps_the_vault_unreadable() = runBlocking {
        val prefs = FlakyPrefs()
        val s = AppSettings(SharedPrefsStore(prefs))
        unlocker.succeed = false; unlocker.error = LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
        val m = AppLockModel(unlocker, clock, scheduler, s, clipboard, eraser, t = EnglishTxt())
        m.unlock()
        prefs.failCommit = { true }
        m.startFreshAnyway()
        assertEquals(0, eraser.calls)
        assertTrue(m.vaultUnreadable); assertTrue(m.offersStartFresh.value)
        assertFalse(s.erasePending)
        assertEquals(EnglishTxt().s(AppLockModel.ERASE_NOT_STARTED_MESSAGE), m.errorMessage.value)
        assertEquals(State.LOCKED, m.st())
        prefs.failCommit = { false }
        m.startFreshAnyway() // works once the flag can be saved
        assertEquals(1, eraser.calls); assertFalse(m.vaultUnreadable); assertFalse(s.erasePending)
    }

    // Unlock error messages

    private fun messageAfter(error: Exception): String? = runBlocking {
        unlocker.succeed = false; unlocker.error = error
        val m = makeModel(); m.unlock()
        assertEquals(State.LOCKED, m.st())
        m.errorMessage.value
    }

    @Test fun user_cancel_is_silent() {
        assertNull(messageAfter(AuthenticationException(BiometricPrompt.ERROR_USER_CANCELED)))
        assertNull(messageAfter(AuthenticationException(BiometricPrompt.ERROR_NEGATIVE_BUTTON)))
    }

    @Test fun system_cancel_is_silent() {
        assertNull(messageAfter(AuthenticationException(BiometricPrompt.ERROR_CANCELED)))
    }

    @Test fun passcode_not_set_says_how_to_fix_it() {
        val text = "Set a screen lock in Settings to use LocalGateKeys."
        assertEquals(text, messageAfter(AuthenticationException(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL)))
        assertEquals(text, messageAfter(VaultKeyException(VaultKeyException.Kind.NO_SCREEN_LOCK)))
    }

    @Test fun biometry_lockout_message() {
        assertEquals(EnglishTxt().s(AppLockModel.BIOMETRY_LOCKOUT_MESSAGE), messageAfter(AuthenticationException(BiometricPrompt.ERROR_LOCKOUT)))
        assertEquals(EnglishTxt().s(AppLockModel.BIOMETRY_LOCKOUT_MESSAGE), messageAfter(AuthenticationException(BiometricPrompt.ERROR_LOCKOUT_PERMANENT)))
        assertEquals(
            "Your fingerprint, face or screen lock is locked after too many attempts. Lock and unlock your phone with its screen lock, then try again.",
            EnglishTxt().s(AppLockModel.BIOMETRY_LOCKOUT_MESSAGE),
        )
    }

    @Test fun other_authentication_errors_include_the_code() {
        assertEquals(
            "Could not unlock (authentication error 1). Try again.",
            messageAfter(AuthenticationException(BiometricPrompt.ERROR_HW_UNAVAILABLE)),
        )
    }

    @Test fun keystore_errors_have_their_message() {
        val text = "Could not read the vault key from this phone's secure storage. Try again."
        assertEquals(text, messageAfter(VaultKeyException(VaultKeyException.Kind.AUTH_REQUIRED)))
        assertEquals(text, messageAfter(VaultKeyException(VaultKeyException.Kind.FAILED)))
    }

    @Test fun store_errors_have_specific_messages() {
        assertEquals("The vault key is missing from this phone's secure storage.",
            messageAfter(LocalStoreException(LocalStoreException.Kind.NO_LOCAL_KEY)))
        assertEquals("The vault key in this phone's secure storage is damaged.",
            messageAfter(LocalStoreException(LocalStoreException.Kind.BAD_LOCAL_KEY)))
        assertEquals("The vault on this phone could not be read (damaged).",
            messageAfter(LocalStoreException(LocalStoreException.Kind.CORRUPT, "state")))
        assertEquals("The vault's files on this phone could not be read or written. Try again.",
            messageAfter(LocalStoreException(LocalStoreException.Kind.IO)))
        assertEquals("Could not unlock. Try again.", messageAfter(LocalStoreException(LocalStoreException.Kind.STALE)))
    }

    @Test fun other_errors_keep_the_generic_message() {
        assertEquals("Could not unlock. Try again.", messageAfter(FakeUnlocker.Denied()))
    }

    // Start fresh anyway

    @Test fun failed_pending_erase_offers_start_fresh() = runBlocking {
        settings.erasePending = true; eraser.failuresLeft = 99
        val m = makeModel(); m.unlock()
        assertTrue(m.eraseFailed); assertTrue(m.offersStartFresh.value); assertEquals(0, unlocker.unlockCalls)
        assertEquals(VaultEraseFailure(listOf("local-key")).text(EnglishTxt()), m.errorMessage.value)
    }

    @Test fun start_fresh_anyway_clears_the_flag_and_the_next_unlock_opens() = runBlocking {
        settings.erasePending = true; eraser.failuresLeft = 99
        val m = makeModel(); m.unlock()
        m.startFreshAnyway()
        assertEquals("deletes what it can once more", 2, eraser.calls)
        assertFalse(settings.erasePending); assertFalse(m.eraseFailed); assertNull(m.errorMessage.value)
        assertEquals(State.LOCKED, m.st())
        m.unlock()
        assertEquals(State.UNLOCKED, m.st())
    }

    // Vault files without their key (key invalidated, vault-key.bin missing, a copied data directory)

    @Test fun vault_without_key_explains_and_offers_start_fresh() = runBlocking {
        unlocker.succeed = false; unlocker.error = LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
        val m = makeModel(); m.unlock()
        assertEquals(State.LOCKED, m.st())
        assertTrue(m.vaultUnreadable)
        assertTrue(m.offersStartFresh.value)
        assertEquals(EnglishTxt().s(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE), m.errorMessage.value)
        assertTrue(EnglishTxt().s(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE).contains("backup"))
        assertFalse("nothing is erased until the person chooses Start fresh", settings.erasePending)
        assertEquals(0, eraser.calls)

        unlocker.succeed = true
        m.startFreshAnyway()
        assertEquals(1, eraser.calls)
        assertFalse(settings.erasePending); assertFalse(m.vaultUnreadable); assertFalse(m.offersStartFresh.value)
        assertNull(m.errorMessage.value)
        assertEquals(State.LOCKED, m.st())
        m.unlock()
        assertEquals(State.UNLOCKED, m.st())
    }

    @Test fun invalidated_key_offers_start_fresh() = runBlocking {
        for (error in listOf(
            LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY),
            VaultKeyException(VaultKeyException.Kind.INVALIDATED),
            VaultKeyException(VaultKeyException.Kind.MISSING),
        )) {
            unlocker.succeed = false; unlocker.error = error
            val m = makeModel(); m.unlock()
            assertEquals(error.toString(), State.LOCKED, m.st())
            assertEquals(error.toString(), EnglishTxt().s(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE), m.errorMessage.value)
            assertTrue(error.toString(), m.vaultUnreadable)
            assertTrue(error.toString(), m.offersStartFresh.value)
            assertNull(m.store)
        }
        assertEquals("never erased without the person's choice", 0, eraser.calls)
        assertFalse(settings.erasePending)
    }

    @Test fun vault_without_key_message_uses_phone_words() {
        assertEquals(
            "This phone has vault files but not their key (for example after restoring a backup), so they cannot be opened. " +
                "Start fresh to erase them and set up an empty vault, then sync with your PC to get your items back.",
            EnglishTxt().s(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE),
        )
        assertEquals(
            "Start fresh anyway?\n\nLocalGateKeys deletes everything it can from this phone and opens a new, empty vault. " +
                "Anything it could not delete stays on this phone but is no longer used. Your PC and the sync folder are not changed.",
            EnglishTxt().s(AppLockModel.START_FRESH_CONFIRM_1),
        )
        assertEquals("Are you sure? This cannot be undone. Start fresh now?", EnglishTxt().s(AppLockModel.START_FRESH_CONFIRM_2))
        assertEquals("Unlock your vault", EnglishTxt().s(R.string.unlock_reason))
    }

    @Test fun vault_without_key_start_fresh_that_fails_falls_back_to_the_erase_flow() = runBlocking {
        unlocker.succeed = false; unlocker.error = LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
        val m = makeModel(); m.unlock()
        eraser.failuresLeft = 99
        m.startFreshAnyway()
        assertTrue("a failed erase is retried before the next unlock", settings.erasePending)
        assertTrue(m.eraseFailed); assertTrue(m.offersStartFresh.value)
        assertEquals(VaultEraseFailure(listOf("local-key")).text(EnglishTxt()), m.errorMessage.value)
    }

    @Test fun start_fresh_is_not_offered_for_other_errors() = runBlocking {
        unlocker.succeed = false; unlocker.error = LocalStoreException(LocalStoreException.Kind.CORRUPT, "x")
        val m = makeModel(); m.unlock()
        assertFalse(m.offersStartFresh.value)
        m.startFreshAnyway()
        assertEquals("Start fresh never runs without being offered", 0, eraser.calls)
    }

    @Test fun start_fresh_is_not_offered_after_a_successful_erase() = runBlocking {
        settings.erasePending = true
        val m = makeModel(); m.unlock()
        assertFalse(m.eraseFailed); assertFalse(m.offersStartFresh.value); assertEquals(State.UNLOCKED, m.st())
    }

    @Test fun user_facing_text_never_names_platform_storage_or_a_passcode() {
        val texts = listOf(
            EnglishTxt().s(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE), EnglishTxt().s(AppLockModel.BIOMETRY_LOCKOUT_MESSAGE), EnglishTxt().s(AppLockModel.START_FRESH_CONFIRM_1),
            EnglishTxt().s(AppLockModel.START_FRESH_CONFIRM_2), EnglishTxt().s(AppLockModel.ERASE_FAILED_MESSAGE), EnglishTxt().s(AppLockModel.ERASE_NOT_STARTED_MESSAGE),
            EnglishTxt().s(VaultEraser.CONFIRM_TEXT_1), EnglishTxt().s(VaultEraser.CONFIRM_TEXT_2),
        ) + (
            listOf<Throwable>(
                AuthenticationException(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL),
                AuthenticationException(BiometricPrompt.ERROR_LOCKOUT),
                AuthenticationException(BiometricPrompt.ERROR_HW_UNAVAILABLE),
            ) + VaultKeyException.Kind.entries.map { VaultKeyException(it) } +
                LocalStoreException.Kind.entries.map { LocalStoreException(it) }
            ).mapNotNull { AppLockModel.message(it, EnglishTxt()) }
        for (t in texts) {
            for (word in listOf("Keychain", "Keystore", "passcode", "iPhone", "Face ID")) {
                assertFalse("'$word' in: $t", t.contains(word, ignoreCase = true))
            }
        }
    }

    @Test fun erase_failure_wording() {
        assertEquals(
            "The vault was not fully erased (could not delete: store files, local-key). Tap Unlock to try erasing again, or Start fresh anyway.",
            VaultEraseFailure(listOf("store files", "local-key")).text(EnglishTxt()),
        )
    }
}
