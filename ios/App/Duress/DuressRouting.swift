import Foundation
import AppShared

/// The Settings actions that take the duress path inside a duress session (Ruling T5a-b; Android `DuressRouting`),
/// apart from the views so the choice is tested: `inDuressSession` is read when the action runs.
@MainActor
struct DuressRouting {
    let inDuressSession: () -> Bool
    let duress: PhoneDuress?
    let throttle: AppPasswordStore?

    /// "Change app password": in a duress session only the second vault's password changes (`localKey` is the
    /// session's key; throttled like the real change, no visible refusal); otherwise `real` runs (the real app
    /// password, with its duress checks).
    func changePassword(localKey: () throws -> [UInt8], current: String, new: String,
                        real: () async throws -> Void) async throws {
        guard inDuressSession() else { return try await real() }
        guard let duress, let throttle else { throw DuressError("generic") }
        var key = try localKey()
        defer { for i in key.indices { key[i] = 0 } }
        let session = key
        try await Task.detached(priority: .userInitiated) {
            try duress.changeSecondPassword(decoyKey: session, current: current, new: new, throttle: throttle)
        }.value
    }

    /// Settings › "Erase this iPhone's vault": in a duress session `lockAndWait` (lock, then this unlock's work) and
    /// only the second vault's data goes (`PhoneDuress.eraseSecondVault`, never the erase-pending flag, so nothing can
    /// turn into a real erase later); otherwise `real` (the full erase). True when the chosen erase finished.
    @discardableResult
    func erase(lockAndWait: () async -> Void, real: () async -> Void) async -> Bool {
        guard inDuressSession() else { await real(); return true }
        await lockAndWait()
        guard let duress else { return false }
        return await Task.detached(priority: .userInitiated) { duress.eraseSecondVault() }.value
    }
}
