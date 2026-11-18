import SwiftUI
import Observation
import AppSharedMac

/// Backup & restore before unlock (Windows `RecoveryPage` on the lock screen): restore a full backup as a new profile
/// (on the create screen: into this empty profile), or verify one. Nothing else changes.
@MainActor @Observable
final class LockBackupModel {
    nonisolated static let title = String(localized: "Backup & restore")
    nonisolated static let intro = String(localized: "Restore a full backup made on this Mac or in LocalGateKeys for Windows. You need its backup password and the master password in use when it was made; that master password then opens the restored vault.")
    nonisolated static let restoredText = String(localized: "Backup restored.")
    nonisolated static let verifiedText = String(localized: "Backup verified. Nothing was changed.")

    let session: MacProfileSession
    var file: URL?
    var backupPassword = ""
    var masterPassword = ""
    var profileName = ""
    private(set) var busy = false
    var message: String?
    var success: String?

    /// Where restored documents go (nil in tests: they stay desktop data).
    @ObservationIgnored private let attachments: () -> BlobFolder?

    init(session: MacProfileSession, attachments: @escaping () -> BlobFolder? = { AttachmentFiles.localFolder() }) {
        self.session = session; self.attachments = attachments
        profileName = String(localized: "Restored")
    }

    /// On the create screen the backup goes into the open, empty profile; on the lock screen into a new one.
    var intoNewProfile: Bool { session.lock.state == .locked }
    /// A new profile needs the app group container (signed builds).
    var canRestoreHere: Bool { session.lock.state == .noVault || session.canUseProfiles }

    var ready: Bool { file != nil && !backupPassword.isEmpty && !masterPassword.isEmpty && !busy }

    func verify() async {
        guard let file, ready else { return }
        busy = true; message = nil; success = nil
        defer { busy = false }
        do {
            _ = try await MacFullBackup.verifyFile(url: file, password: backupPassword, vaultPassword: masterPassword)
            success = Self.verifiedText
        } catch { message = MacFullBackup.describe(error) }
    }

    /// Checks the backup, makes the vault (new profile, or this empty one) with the backup's master password, then
    /// restores into it; the vault is left open. A failure after the vault was made removes it again.
    func restore() async -> Bool {
        guard let file, ready, canRestoreHere else { return false }
        busy = true; message = nil; success = nil
        defer { busy = false }
        let (backup, master) = (backupPassword, masterPassword)
        do { _ = try await MacFullBackup.verifyFile(url: file, password: backup, vaultPassword: master) } catch {
            message = MacFullBackup.describe(error); return false
        }
        let madeProfile = intoNewProfile
        if madeProfile {
            guard session.create(name: profileName) else { message = session.message; return false }
        }
        let lock = session.lock
        await lock.create(password: master, confirm: master, touchID: false)
        guard lock.state == .unlocked, let store = lock.store, let profile = lock.desktopProfile else {
            message = lock.message ?? String(localized: "Full backup restore failed")
            await undo(madeProfile: madeProfile, master: master)
            return false
        }
        let restore = MacFullBackup(store: store, profile: profile, passwords: lock, gate: StrictItemGate(passwords: lock),
                                    local: lock, attachmentFolder: attachments())
        do {
            try await restore.restoreIntoNewVault(url: file, password: backup, vaultPassword: master)
        } catch {
            message = MacFullBackup.describe(error)
            await undo(madeProfile: madeProfile, master: master)
            return false
        }
        // Reopen so the window loads the restored items (and Pro, sync and schedules start for them).
        lock.lock()
        await lock.unlock(password: master)
        success = Self.restoredText
        return true
    }

    /// The vault made for a failed restore goes: the new profile is removed, or this profile back to no vault.
    private func undo(madeProfile: Bool, master: String) async {
        let lock = session.lock
        if lock.state == .unlocked { lock.lock() }
        if madeProfile {
            let keep = message
            _ = await session.removeActive(password: master)
            message = keep
        } else {
            session.eraseOpenProfile()
        }
    }
}

struct LockBackupSheet: View {
    @Bindable var model: LockBackupModel
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(LockBackupModel.title).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
            Text(LockBackupModel.intro).font(.callout).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Choose backup…") {
                    model.file = RecoveryPanels.chooseBackup(prompt: String(localized: "Choose"),
                                                             message: String(localized: "Choose a LocalGateKeys full backup (.lgk)."))
                }
                .buttonStyle(PillButtonStyle(primary: false))
                Text(model.file?.lastPathComponent ?? String(localized: "No file chosen"))
                    .font(.callout).foregroundStyle(theme.textMuted).lineLimit(1).truncationMode(.middle)
            }
            SecureField("Backup password", text: $model.backupPassword).glassField()
            SecureField("Master password when the backup was made", text: $model.masterPassword).glassField()
            if model.intoNewProfile {
                TextField("Name of the new profile", text: $model.profileName).glassField()
            }
            if let message = model.message { MessageLine(text: message) }
            if let success = model.success { Text(success).font(.callout).foregroundStyle(theme.success) }
            HStack {
                Button("Close", action: onClose).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Verify") { Task { await model.verify() } }
                    .buttonStyle(PillButtonStyle(primary: false)).disabled(!model.ready)
                Button(model.intoNewProfile ? String(localized: "Restore as new profile") : String(localized: "Restore")) {
                    Task { if await model.restore() { onClose() } }
                }
                .buttonStyle(PillButtonStyle(primary: true)).disabled(!model.ready || !model.canRestoreHere)
            }
            if model.busy { ProgressView().controlSize(.small) }
        }
        .padding(24)
        .frame(width: 460)
    }
}
