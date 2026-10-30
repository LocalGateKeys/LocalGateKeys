import Foundation
import Security
import AuthenticationServices
import AppShared

/// Erases this iPhone's vault. Fakes stand in for it in `AppLockModel` tests.
protocol VaultErasing: Sendable {
    func erase() async throws
}

/// The steps that failed, by name only (never a value).
struct VaultEraseFailure: Error, Equatable {
    let steps: [String]
    var message: String {
        let list = steps.joined(separator: ", ")
        return String(localized: "The vault was not fully erased (could not delete: \(list)). Tap Unlock to try erasing again, or Start fresh anyway.")
    }
}

/// "Erase this iPhone's vault": deletes the local store, the Safari save files, every Keychain item of this install in each given
/// access group and the published AutoFill identities. Every step is attempted even when an earlier one
/// fails; the failures are thrown together. Missing items are not errors, so erasing again is safe.
/// The next unlock is a first run. Never touches the desktop or the synced folder.
///
/// The AutoFill identities hold only usernames and domains, so removing them is best-effort and never
/// decides success: skipped while LocalGateKeys is not an enabled AutoFill provider (the system refuses
/// with `storeDisabled` then), and any other failure is retried by the next identity refresh.
struct VaultEraser: VaultErasing {
    let directory: @Sendable () throws -> URL
    /// The shared group, the app-only group and the Safari group: each slot is deleted from each.
    let keychains: [any KeychainVault]
    let identities: any CredentialIdentityStoring
    /// Asks the next identity refresh to remove the identities again.
    var scheduleIdentityRetry: @Sendable () -> Void = {}
    /// Deletes the store directory (a seam: tests make it fail).
    var removeDirectory: @Sendable (URL) throws -> Void = { try FileManager.default.removeItem(at: $0) }
    var now: @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) }
    /// `<app group>/SafariSave` (index and inbox), found without creating it; nil: nothing to delete.
    var safariDirectory: @Sendable () throws -> URL? = { nil }
    /// The unsaved editor draft (Task 6, `EditorDraftStore`); nil: none. Failure name "draft".
    var draftFile: @Sendable () -> URL? = { nil }

    /// Two confirmations, in the style of Leave and Reset sync (`SyncWording`).
    static var confirmText1: String { String(localized: "Erase this iPhone's vault?\n\nThis deletes every item, the vault's keys and its sync settings from this iPhone. Your PC and the sync folder are not changed. If this iPhone was your only copy, the items are gone.") }
    static var confirmText2: String { String(localized: "Are you sure? This cannot be undone. Erase this iPhone's vault now?") }

    /// Context-free vaults for the shared, app-only and Safari groups (deleting needs no Face ID; the
    /// session's authenticated context is gone once the app locks).
    static func live(settings: AppSettings = .shared) -> VaultEraser {
        var groups: [String?] = [AppGroup.keychainAccessGroup]
        for group in [AppGroup.appKeychainAccessGroup, AppGroup.safariKeychainAccessGroup] {
            if let g = group, !g.isEmpty, !g.hasPrefix("."), !g.contains("$(") { groups.append(g) }
        }
        return VaultEraser(directory: { try AppGroup.vaultDirectory() },
                           keychains: groups.map { SystemKeychainVault(accessGroup: $0) },
                           identities: SystemCredentialIdentityStore(),
                           scheduleIdentityRetry: { settings.identityRemovalPending = true },
                           safariDirectory: { try SafariSaveFiles.location() },
                           draftFile: { EditorDraftStore.location() })
    }

    func erase() async throws {
        var failed: [String] = []
        do {
            let dir = try directory()
            LocalStore.removeSetAside(nextTo: dir)   // earlier leftovers, best effort
            if FileManager.default.fileExists(atPath: dir.path) {
                do { try removeDirectory(dir) } catch {
                    // Not deletable now: move it out of the way so the next unlock starts empty (no
                    // vaultWithoutKey loop). The set-aside copy is deleted later, best effort.
                    try LocalStore.setAside(dir, now: now())
                }
            }
        } catch {
            failed.append("store files")
        }
        // Safari save files: best effort and never a failure, since both their keys are deleted below and
        // what is left can no longer be read.
        if let safari = try? safariDirectory(), FileManager.default.fileExists(atPath: safari.path) {
            try? FileManager.default.removeItem(at: safari)
        }
        if let draft = draftFile(), !EditorDraftStore.deleteFile(draft) { failed.append("draft") }
        // Task 7: the app password file and the Face ID shortcut (before the slots, so a failed slot delete
        // never leaves password mode pointing at a deleted vault).
        if let appPassword = AppPasswordStore.shared(), !appPassword.removeAll() { failed.append("app-password") }
        for slot in VaultSlot.allCases {
            for keychain in keychains {
                do { try keychain.delete(slot) }
                catch KeychainVaultError.status(errSecMissingEntitlement) {}   // group unusable: nothing stored there
                catch KeychainVaultError.status(let st) where st == errSecInteractionNotAllowed || st == errSecAuthFailed {
                    // Refused while the device cannot authenticate: done only if the item is provably gone.
                    let gone = (keychain as? any KeychainPresenceChecking)?.presence(slot) == .absent
                    if !gone, !failed.contains(slot.rawValue) { failed.append(slot.rawValue) }
                }
                catch { if !failed.contains(slot.rawValue) { failed.append(slot.rawValue) } }
            }
        }
        await removeIdentities()
        if !failed.isEmpty { throw VaultEraseFailure(steps: failed) }
    }

    private func removeIdentities() async {
        guard await identities.isEnabled() else { return }   // nothing the system would offer
        do { try await identities.removeAll() }
        catch let e as ASCredentialIdentityStoreError where e.code == .storeDisabled {}
        catch { scheduleIdentityRetry() }
    }
}
