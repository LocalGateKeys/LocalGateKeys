import XCTest
import LocalAuthentication
import AppShared
@testable import LocalGateKeys

@MainActor
final class AppLockModelTests: XCTestCase {
    var clock: TestClock!, scheduler: ManualScheduler!, unlocker: FakeUnlocker!, defaults: UserDefaults!
    var pasteboard: FakePasteboard!, clipboard: SecretClipboard!, settings: AppSettings!, eraser: FakeEraser!

    override func setUp() async throws {
        clock = TestClock(1_790_000_000); scheduler = ManualScheduler(clock: clock); unlocker = FakeUnlocker()
        defaults = UserDefaults(suiteName: "lock-\(UUID().uuidString)")!
        settings = AppSettings(defaults: defaults); eraser = FakeEraser()
        pasteboard = FakePasteboard(); clipboard = SecretClipboard(pasteboard: pasteboard, clock: clock)
    }

    func makeModel() -> AppLockModel {
        AppLockModel(unlocker: unlocker, clock: clock, scheduler: scheduler, settings: settings,
                     clipboard: clipboard, eraser: eraser)
    }

    func unlocked() async -> AppLockModel {
        let m = makeModel(); await m.unlock(); XCTAssertEqual(m.state, .unlocked); return m
    }

    func test_starts_locked_and_unlocks_with_device_auth() async {
        let m = makeModel()
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.store)
        await m.unlock()
        XCTAssertEqual(m.state, .unlocked); XCTAssertNotNil(m.store); XCTAssertEqual(unlocker.unlockCalls, 1)
    }

    func test_unlock_during_erase_returns_early() async {
        let m = await unlocked()
        let opens = unlocker.unlockCalls
        await m.eraseAndLock { await m.unlock() }
        XCTAssertEqual(eraser.calls, 1, "no second erase")
        XCTAssertEqual(unlocker.unlockCalls, opens, "no vault opened")
        XCTAssertEqual(m.state, .locked)
    }

    func test_failed_auth_stays_locked() async {
        unlocker.succeed = false
        let m = makeModel(); await m.unlock()
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.store); XCTAssertNotNil(m.errorMessage)
    }

    func test_default_background_delay_is_immediately() {
        XCTAssertEqual(settings.autoLockDelay, .immediately)
    }

    func test_background_locks_immediately_by_default() async {
        let m = await unlocked()
        m.didEnterBackground()
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.store); XCTAssertEqual(unlocker.lockCalls, 1)
    }

    func test_background_delay_locks_only_after_the_delay() async {
        settings.autoLockDelay = .oneMinute
        let m = await unlocked()
        m.didEnterBackground(); XCTAssertEqual(m.state, .unlocked)
        clock.now += 59; m.willEnterForeground(); XCTAssertEqual(m.state, .unlocked)
        m.didEnterBackground(); clock.now += 60; m.willEnterForeground()
        XCTAssertEqual(m.state, .locked)
    }

    func test_idle_locks_after_five_minutes() async {
        let m = await unlocked()
        scheduler.advance(by: 299); XCTAssertEqual(m.state, .unlocked)
        scheduler.advance(by: 1); XCTAssertEqual(m.state, .locked)
    }

    func test_activity_restarts_the_idle_timer() async {
        let m = await unlocked()
        scheduler.advance(by: 200); m.noteActivity()
        scheduler.advance(by: 299); XCTAssertEqual(m.state, .unlocked)
        scheduler.advance(by: 1); XCTAssertEqual(m.state, .locked)
    }

    func test_idle_time_spent_in_background_counts_on_return() async {
        settings.autoLockDelay = .fifteenMinutes
        let m = await unlocked()
        m.didEnterBackground(); clock.now += 301   // suspended: no timer fires
        m.willEnterForeground()
        XCTAssertEqual(m.state, .locked)
    }

    func test_lock_cancels_the_idle_timer() async {
        let m = await unlocked()
        XCTAssertEqual(scheduler.pending, 1)
        m.lock()
        XCTAssertEqual(scheduler.pending, 0); XCTAssertEqual(m.state, .locked)
    }

    func test_activity_while_locked_does_nothing() {
        let m = makeModel(); m.noteActivity()
        XCTAssertEqual(scheduler.pending, 0)
    }

    func test_lock_during_in_flight_unlock_wins() async {
        let m = makeModel()
        unlocker.duringUnlock = { m.lock() }
        await m.unlock()
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.store); XCTAssertEqual(scheduler.pending, 0)
    }

    func test_lock_drops_the_store_holding_decoded_records() async {
        let m = await unlocked()
        m.lock()
        XCTAssertNil(m.store)
    }

    func test_lock_clears_our_clipboard_copy() async {
        let m = await unlocked()
        clipboard.copy("s3cret")
        m.lock()
        XCTAssertTrue(pasteboard.items.isEmpty)
    }

    func test_background_lock_keeps_the_copy_for_pasting_elsewhere() async {
        let m = await unlocked()
        XCTAssertEqual(settings.autoLockDelay, .immediately)
        clipboard.copy("123456")
        m.didEnterBackground()
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(pasteboard.items.first?["public.utf8-plain-text"] as? String, "123456")
    }

    func test_delayed_background_lock_keeps_the_copy() async {
        settings.autoLockDelay = .oneMinute
        let m = await unlocked()
        clipboard.copy("123456")
        m.didEnterBackground(); clock.now += 60; m.willEnterForeground()
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(pasteboard.items.first?["public.utf8-plain-text"] as? String, "123456")
    }

    func test_lock_leaves_a_later_foreign_copy_alone() async {
        let m = await unlocked()
        clipboard.copy("s3cret")
        pasteboard.setItems([["public.utf8-plain-text": "user text"]], options: [:])   // another app copied
        m.lock()
        XCTAssertEqual(pasteboard.items.first?["public.utf8-plain-text"] as? String, "user text")
    }

    func test_idle_timeout_follows_the_setting() async {
        settings.idleLock = .oneMinute
        let m = await unlocked()
        scheduler.advance(by: 59); XCTAssertEqual(m.state, .unlocked)
        scheduler.advance(by: 1); XCTAssertEqual(m.state, .locked)
    }

    func test_idle_never_schedules_no_timer_and_foreground_keeps_unlocked() async {
        settings.idleLock = .never; settings.autoLockDelay = .oneHour
        let m = await unlocked()
        XCTAssertEqual(scheduler.pending, 0)
        scheduler.advance(by: 100_000); XCTAssertEqual(m.state, .unlocked)
        m.didEnterBackground(); clock.now += 3599; m.willEnterForeground()
        XCTAssertEqual(m.state, .unlocked)
    }

    func test_one_hour_background_delay_locks_after_an_hour() async {
        settings.autoLockDelay = .oneHour; settings.idleLock = .never
        let m = await unlocked()
        m.didEnterBackground(); clock.now += 3600; m.willEnterForeground()
        XCTAssertEqual(m.state, .locked)
    }

    func test_changing_the_idle_setting_takes_effect_on_next_activity() async {
        let m = await unlocked()
        settings.idleLock = .fifteenMinutes
        m.noteActivity()
        scheduler.advance(by: 300); XCTAssertEqual(m.state, .unlocked)
        scheduler.advance(by: 600); XCTAssertEqual(m.state, .locked)
    }

    func test_clipboard_expiry_uses_the_setting() {
        settings.clipboardExpiry = .thirtySeconds
        SecretClipboard(pasteboard: pasteboard, clock: clock, settings: settings).copy("x")
        XCTAssertEqual(pasteboard.options[.expirationDate] as? Date, Date(timeIntervalSince1970: TimeInterval(clock.now + 30)))
        settings.clipboardExpiry = .fiveMinutes
        SecretClipboard(pasteboard: pasteboard, clock: clock, settings: settings).copy("y")
        XCTAssertEqual(pasteboard.options[.expirationDate] as? Date, Date(timeIntervalSince1970: TimeInterval(clock.now + 300)))
    }

    func test_erase_locks_first_even_when_it_fails_and_unlock_retries_it() async {
        let m = await unlocked()
        eraser.failuresLeft = 2
        var stateDuringWait: AppLockModel.State?
        await m.eraseAndLock { stateDuringWait = m.state; XCTAssertTrue(self.settings.erasePending, "set before the erase") }
        XCTAssertEqual(stateDuringWait, .locked, "locked before anything else runs")
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.store)
        XCTAssertEqual(m.errorMessage, VaultEraseFailure(steps: ["local-key"]).message)
        await m.unlock()   // the retry fails again: stays locked, no unlock attempted
        XCTAssertEqual(m.state, .locked); XCTAssertEqual(eraser.calls, 2); XCTAssertEqual(unlocker.unlockCalls, 1)
        await m.unlock()   // the retry succeeds, then the unlock runs (a first run)
        XCTAssertEqual(eraser.calls, 3); XCTAssertEqual(m.state, .unlocked); XCTAssertNil(m.errorMessage)
    }

    func test_successful_erase_locks_with_no_message() async {
        let m = await unlocked()
        await m.eraseAndLock()
        XCTAssertEqual(m.state, .locked); XCTAssertNil(m.errorMessage); XCTAssertFalse(settings.erasePending)
    }

    func test_pending_erase_survives_a_relaunch_and_unlock_retries_it() async {
        let m = await unlocked()
        eraser.failuresLeft = 1
        await m.eraseAndLock()
        XCTAssertTrue(settings.erasePending)
        // Relaunch: a new model over the same app-group defaults.
        let relaunched = AppLockModel(unlocker: unlocker, clock: clock, scheduler: scheduler,
                                      settings: AppSettings(defaults: defaults), clipboard: clipboard, eraser: eraser)
        await relaunched.unlock()
        XCTAssertEqual(eraser.calls, 2, "retried before unlocking")
        XCTAssertFalse(settings.erasePending)
        XCTAssertEqual(relaunched.state, .unlocked)
    }

    func test_crash_mid_erase_leaves_the_flag_set() async {
        settings.erasePending = true   // what a crash during erase() leaves behind
        let m = makeModel()
        eraser.failuresLeft = 1
        await m.unlock()
        XCTAssertEqual(m.state, .locked); XCTAssertEqual(unlocker.unlockCalls, 0); XCTAssertTrue(settings.erasePending)
    }

    func test_healthy_vault_is_never_erased() async {
        let m = await unlocked(); m.lock()
        await m.unlock()
        XCTAssertEqual(eraser.calls, 0); XCTAssertEqual(m.state, .unlocked)
    }

    // MARK: scene phase (Face ID sheet makes the scene inactive, then active again)

    func test_cancelled_face_id_is_not_reprompted_on_inactive_to_active() async {
        unlocker.succeed = false
        let m = makeModel()
        await m.sceneBecameActive()                 // launch: prompts once
        XCTAssertEqual(unlocker.unlockCalls, 1)
        // The Face ID sheet closing: inactive -> active. No new prompt; the error stays visible.
        await m.sceneBecameActive()
        XCTAssertEqual(unlocker.unlockCalls, 1)
        XCTAssertEqual(m.state, .locked); XCTAssertNotNil(m.errorMessage)
    }

    func test_return_from_background_prompts_again() async {
        unlocker.succeed = false
        let m = makeModel()
        await m.sceneBecameActive()
        m.didEnterBackground()
        await m.sceneBecameActive()
        XCTAssertEqual(unlocker.unlockCalls, 2)
        await m.sceneBecameActive()                 // inactive -> active again: no third prompt
        XCTAssertEqual(unlocker.unlockCalls, 2)
    }

    func test_background_lock_then_return_prompts_and_unlocks() async {
        let m = makeModel()
        await m.sceneBecameActive(); XCTAssertEqual(m.state, .unlocked)
        m.didEnterBackground(); XCTAssertEqual(m.state, .locked)   // immediately, by default
        await m.sceneBecameActive()
        XCTAssertEqual(m.state, .unlocked); XCTAssertEqual(unlocker.unlockCalls, 2)
    }

    func test_manual_unlock_still_works_after_a_cancel() async {
        unlocker.succeed = false; unlocker.error = LAError(.userCancel)
        let m = makeModel()
        await m.sceneBecameActive()
        unlocker.succeed = true
        await m.unlock()
        XCTAssertEqual(m.state, .unlocked); XCTAssertEqual(unlocker.unlockCalls, 2)
    }

    // MARK: unlock error messages

    func message(after error: any Error) async -> String? {
        unlocker.succeed = false; unlocker.error = error
        let m = makeModel(); await m.unlock()
        XCTAssertEqual(m.state, .locked)
        return m.errorMessage
    }

    func test_user_cancel_is_silent() async {
        let msg = await message(after: LAError(.userCancel))
        XCTAssertNil(msg)
    }

    func test_system_cancel_is_silent() async {
        let msg = await message(after: LAError(.systemCancel))
        XCTAssertNil(msg)
    }

    func test_passcode_not_set_says_how_to_fix_it() async {
        let msg = await message(after: LAError(.passcodeNotSet))
        XCTAssertEqual(msg, "Set a device passcode in Settings to use LocalGateKeys.")
    }

    func test_biometry_lockout_message() async {
        let msg = await message(after: LAError(.biometryLockout))
        XCTAssertEqual(msg, AppLockModel.biometryLockoutMessage)
    }

    func test_keychain_status_message_includes_the_code() async {
        let msg = await message(after: KeychainVaultError.status(errSecInteractionNotAllowed))
        XCTAssertEqual(msg, "Could not read the vault key from the Keychain (error -25308). Try again.")
    }

    func test_store_errors_have_specific_messages() async {
        let noKey = await message(after: LocalStoreError.noLocalKey)
        XCTAssertEqual(noKey, "The vault key is missing from this iPhone's Keychain.")
        let noContainer = await message(after: LocalStoreError.noContainer)
        XCTAssertEqual(noContainer, "The vault's storage on this iPhone is unavailable.")
        let corrupt = await message(after: LocalStoreError.corrupt("state"))
        XCTAssertEqual(corrupt, "The vault on this iPhone could not be read (damaged).")
    }

    func test_other_errors_keep_the_generic_message() async {
        let msg = await message(after: FakeUnlocker.Denied())
        XCTAssertEqual(msg, "Could not unlock. Try again.")
    }

    // MARK: Start fresh anyway

    func test_failed_pending_erase_offers_start_fresh() async {
        settings.erasePending = true; eraser.failuresLeft = 99
        let m = makeModel(); await m.unlock()
        XCTAssertTrue(m.eraseFailed); XCTAssertEqual(unlocker.unlockCalls, 0)
        XCTAssertEqual(m.errorMessage, VaultEraseFailure(steps: ["local-key"]).message)
    }

    func test_start_fresh_anyway_clears_the_flag_and_the_next_unlock_opens() async {
        settings.erasePending = true; eraser.failuresLeft = 99
        let m = makeModel(); await m.unlock()
        await m.startFreshAnyway()
        XCTAssertEqual(eraser.calls, 2, "deletes what it can once more")
        XCTAssertFalse(settings.erasePending); XCTAssertFalse(m.eraseFailed); XCTAssertNil(m.errorMessage)
        XCTAssertEqual(m.state, .locked)
        await m.unlock()
        XCTAssertEqual(m.state, .unlocked)
    }

    // MARK: vault files without their key (restored backup)

    func test_vault_without_key_explains_and_offers_start_fresh() async {
        unlocker.succeed = false; unlocker.error = LocalStoreError.vaultWithoutKey
        let m = makeModel(); await m.unlock()
        XCTAssertEqual(m.state, .locked)
        XCTAssertTrue(m.vaultUnreadable)
        XCTAssertTrue(m.offersStartFresh)
        XCTAssertEqual(m.errorMessage, AppLockModel.vaultWithoutKeyMessage)
        XCTAssertTrue(AppLockModel.vaultWithoutKeyMessage.contains("backup"))
        XCTAssertFalse(settings.erasePending, "nothing is erased until the person chooses Start fresh")
        XCTAssertEqual(eraser.calls, 0)

        unlocker.succeed = true
        await m.startFreshAnyway()
        XCTAssertEqual(eraser.calls, 1)
        XCTAssertFalse(settings.erasePending); XCTAssertFalse(m.vaultUnreadable); XCTAssertFalse(m.offersStartFresh)
        XCTAssertNil(m.errorMessage)
        XCTAssertEqual(m.state, .locked)
        await m.unlock()
        XCTAssertEqual(m.state, .unlocked)
    }

    func test_vault_without_key_start_fresh_that_fails_falls_back_to_the_erase_flow() async {
        unlocker.succeed = false; unlocker.error = LocalStoreError.vaultWithoutKey
        let m = makeModel(); await m.unlock()
        eraser.failuresLeft = 99
        await m.startFreshAnyway()
        XCTAssertTrue(settings.erasePending, "a failed erase is retried before the next unlock")
        XCTAssertTrue(m.eraseFailed); XCTAssertTrue(m.offersStartFresh)
        XCTAssertEqual(m.errorMessage, VaultEraseFailure(steps: ["local-key"]).message)
    }

    func test_start_fresh_is_not_offered_for_other_errors() async {
        unlocker.succeed = false; unlocker.error = LocalStoreError.corrupt("x")
        let m = makeModel(); await m.unlock()
        XCTAssertFalse(m.offersStartFresh)
        await m.startFreshAnyway()
        XCTAssertEqual(eraser.calls, 0, "Start fresh never runs without being offered")
    }

    func test_start_fresh_is_not_offered_after_a_successful_erase() async {
        settings.erasePending = true
        let m = makeModel(); await m.unlock()
        XCTAssertFalse(m.eraseFailed); XCTAssertEqual(m.state, .unlocked)
    }
}

final class FakeEraser: VaultErasing, @unchecked Sendable {
    var failuresLeft = 0
    private(set) var calls = 0
    func erase() async throws {
        calls += 1
        if failuresLeft > 0 { failuresLeft -= 1; throw VaultEraseFailure(steps: ["local-key"]) }
    }
}
