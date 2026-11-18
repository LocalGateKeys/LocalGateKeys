import SwiftUI
import AppSharedMac

extension Color {
    /// `#RRGGBB` (Windows profile colours); the accent blue for anything else.
    init(profileHex hex: String) {
        let digits = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        guard digits.count == 6, let v = UInt32(digits, radix: 16) else { self = Color(red: 0.16, green: 0.78, blue: 0.98); return }
        self = Color(red: Double((v >> 16) & 0xFF) / 255, green: Double((v >> 8) & 0xFF) / 255, blue: Double(v & 0xFF) / 255)
    }
}

/// A profile's initial in its colour (lock screen chips and the chooser).
struct ProfileBadge: View {
    let profile: ProfileRecord
    var size: CGFloat = 28
    var body: some View {
        Text(profile.initial)
            .font(.system(size: size * 0.46, weight: .semibold)).foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(Color(profileHex: profile.color), in: Circle())
            .accessibilityHidden(true)
    }
}

/// Above the lock and create panels: the open profile's name, and chips for the others (Windows `Unlock.svelte`).
struct ProfileHeader: View {
    @Bindable var session: MacProfileSession
    @Environment(\.macTheme) private var theme

    var body: some View {
        if session.canUseProfiles && session.hasSeveral {
            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    ForEach(session.profiles) { p in
                        Button { session.open(p.id) } label: {
                            ProfileBadge(profile: p, size: p.id == session.active.id ? 34 : 26)
                                .opacity(p.id == session.active.id ? 1 : 0.7)
                        }
                        .buttonStyle(.plain)
                        .help(p.name)
                        .accessibilityLabel(p.name)
                        .accessibilityAddTraits(p.id == session.active.id ? .isSelected : [])
                        .disabled(session.lock.isBusy)
                    }
                }
                Text(session.active.name).font(.headline).foregroundStyle(theme.text)
            }
            .frame(maxWidth: .infinity)
        }
    }
}

/// Below the lock and create panels' buttons: Backup & restore and Use another profile.
struct LockScreenLinks: View {
    @Bindable var session: MacProfileSession
    @State private var backup: LockBackupModel?

    var body: some View {
        // Side by side, or one under the other when a language's labels don't fit (German).
        ViewThatFits(in: .horizontal) {
            HStack { backupLink; if session.canUseProfiles { Spacer(); profileLink } }
            VStack(spacing: 6) { backupLink; if session.canUseProfiles { profileLink } }.frame(maxWidth: .infinity)
        }
        .buttonStyle(.link)
        .font(.callout)
        .disabled(session.lock.isBusy)
        .sheet(item: $backup) { model in
            LockBackupSheet(model: model, onClose: { backup = nil }).macThemed()
        }
        .sheet(isPresented: $session.choosing) {
            ProfileChooserSheet(session: session, onClose: { session.choosing = false }).macThemed()
        }
    }
}

private extension LockScreenLinks {
    var backupLink: some View {
        Button("Backup & restore…") { backup = LockBackupModel(session: session) }.fixedSize()
    }
    var profileLink: some View {
        Button("Use another profile…") { session.message = nil; session.choosing = true }.fixedSize()
    }
}

extension LockBackupModel: Identifiable {
    nonisolated var id: ObjectIdentifier { ObjectIdentifier(self) }
}

/// Pick, add, rename or remove profiles (Windows `ProfileChooser`). Removing applies to the open profile and asks
/// for its master password.
struct ProfileChooserSheet: View {
    @Bindable var session: MacProfileSession
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var newName = ""
    @State private var renaming: String?
    @State private var renameText = ""
    @State private var removing = false
    @State private var removePassword = ""
    @State private var showUpgrade = false
    /// Sub-plan 12: the free plan holds one vault (profile); a second one asks for Pro. While locked, Pro is the App
    /// Store purchase (a licence key sits inside a vault and is known once it is unlocked).
    private var pro: ProModel { MacAppEnvironment.pro }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Profiles").font(.title2.weight(.semibold)).foregroundStyle(theme.text)
            Text("Each profile is a separate vault with its own master password, Touch ID, sync and backups. AutoFill and Safari use the profile opened last.")
                .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 0) {
                ForEach(session.profiles) { p in
                    HStack(spacing: 10) {
                        ProfileBadge(profile: p)
                        if renaming == p.id {
                            TextField("Name", text: $renameText).glassField()
                                .onSubmit { if session.rename(p.id, to: renameText) { renaming = nil } }
                            Button("Save") { if session.rename(p.id, to: renameText) { renaming = nil } }
                                .buttonStyle(PillButtonStyle(primary: false))
                        } else {
                            Text(p.name).foregroundStyle(theme.text)
                            if p.id == session.active.id {
                                Text("Open").font(.caption).foregroundStyle(theme.textMuted)
                            }
                            Spacer()
                            Button("Rename") { renaming = p.id; renameText = p.name }.buttonStyle(.link)
                            if p.id != session.active.id {
                                Button("Open") { session.open(p.id) }.buttonStyle(PillButtonStyle(primary: false))
                            }
                        }
                    }
                    .padding(.vertical, 8)
                    Divider()
                }
            }
            HStack {
                TextField("New profile name", text: $newName).glassField().onSubmit(add)
                Button("Add profile", action: add).buttonStyle(PillButtonStyle(primary: false))
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if session.hasSeveral {
                if removing {
                    Text(MacProfileSession.removeText).font(.callout).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                    if session.lock.state == .locked {
                        SecureField("Master password of \(session.active.name)", text: $removePassword).glassField()
                    }
                    HStack {
                        Button("Cancel") { removing = false; removePassword = "" }.buttonStyle(PillButtonStyle(primary: false))
                        Button("Remove \(session.active.name)", role: .destructive) {
                            let pw = removePassword
                            Task { if await session.removeActive(password: pw) { removing = false; removePassword = "" } }
                        }
                        .buttonStyle(PillButtonStyle(primary: false))
                        .disabled(session.lock.state == .locked && removePassword.isEmpty)
                    }
                } else {
                    Button("Remove \(session.active.name)…") { removing = true; session.message = nil }
                        .buttonStyle(.link).foregroundStyle(theme.danger)
                }
            }
            if let message = session.message { MessageLine(text: message) }
            HStack {
                Spacer()
                Button("Done", action: onClose).buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 460)
        .sheet(isPresented: $showUpgrade) {
            MacUpgradeSheet(pro: pro, reason: .profiles, onClose: { showUpgrade = false }).macThemed()
        }
    }

    nonisolated static func needsPro(profileCount: Int, isPro: Bool) -> Bool { !isPro && profileCount >= 1 }

    private func add() {
        guard !Self.needsPro(profileCount: session.profiles.count, isPro: pro.isPro) else { showUpgrade = true; return }
        let name = newName
        if session.create(name: name) { newName = "" }
    }
}
