import SwiftUI
import LGKCore
import AppSharedMac

/// What Settings › Unlocking › Key file and YubiKey needs from the vault (`MacLockModel`): the factors on this Mac's
/// `master-key.json` (design §4.7: factors attach to the master password wrapper, per device, never synced).
@MainActor
protocol FactorService: AnyObject {
    var factorSpecs: [FactorSpec] { get }
    var factorsAlwaysAsk: Bool { get }
    /// "Remember the key file location on this Mac" (off: "Don't remember").
    var rememberKeyFile: Bool { get set }
    var rememberedKeyFileName: String? { get }
    /// "Always ask" is on with a factor set: Touch ID is off and cannot be turned on.
    var touchIDOffForFactors: Bool { get }
    var yubiKeyPrompt: YubiKeyPrompt { get }
    /// Each change checks the master password with today's factors and returns the line to show.
    func addKeyFile(url: URL, password: String) async throws -> String
    func createKeyFile(at url: URL, password: String) async throws -> String
    func addYubiKey(slot: Int, password: String) async throws -> String
    func removeFactor(_ kind: FactorKind, password: String) async throws -> String
    func checkBackupYubiKey() async throws -> String
    func setFactorsAlwaysAsk(_ on: Bool) throws -> String
}

/// The page's lines: Windows `factors.*` keys (translations come from the Windows catalogs), and `factors.mac.*` where
/// Windows names its own shortcuts (Windows Hello, security key, camera) or "this PC".
enum FactorTexts {
    static var section: String { String(localized: "factors.page.section", defaultValue: "Key file and YubiKey") }
    static var keyFile: String { String(localized: "factors.keyFile", defaultValue: "Key file") }
    static var keyFileOn: String { String(localized: "factors.keyFileOn", defaultValue: "Set: needed with the master password") }
    static var keyFileNone: String { String(localized: "factors.page.keyFileNone", defaultValue: "No key file") }
    static var yubiKey: String { String(localized: "factors.yubikey", defaultValue: "YubiKey") }
    static func yubiKeyOn(slot: Int) -> String {
        let s = String(slot)
        return String(localized: "factors.yubikeyOn", defaultValue: "Set (slot \(s)): needed with the master password")
    }
    static var yubiKeyNone: String { String(localized: "factors.page.yubikeyNone", defaultValue: "No YubiKey") }
    static var addKeyFile: String { String(localized: "factors.page.addKeyFile", defaultValue: "Add key file…") }
    static var createKeyFile: String { String(localized: "factors.page.createKeyFile", defaultValue: "Create key file…") }
    static var addYubiKey: String { String(localized: "factors.page.addYubikey", defaultValue: "Add YubiKey") }
    static var checkBackup: String { String(localized: "factors.page.checkBackup", defaultValue: "Check a backup YubiKey") }
    static var slot: String { String(localized: "factors.page.slot", defaultValue: "Slot") }
    static var hint: String {
        String(localized: "factors.addHint",
               defaultValue: "A key file or YubiKey is then needed together with the master password to unlock this vault. The recovery phrase still opens the vault without them.")
    }
    static var yubiKeySetup: String {
        String(localized: "factors.yubikeySetup",
               defaultValue: "LocalGateKeys never programs your YubiKey. Set it up in Yubico Authenticator: Slots, Challenge-response, HMAC-SHA1, slot 2 (or slot 1). A backup YubiKey needs the same secret.")
    }
    static var backupHint: String { String(localized: "factors.page.backupHint", defaultValue: "To check a backup YubiKey, plug in only that one.") }
    static var alwaysAskTitle: String { String(localized: "factors.alwaysAskTitle", defaultValue: "Always ask for the key file / YubiKey") }
    static var alwaysAskNote: String {
        String(localized: "factors.mac.alwaysAskNote", defaultValue: "Turns off Touch ID unlock while a key file or YubiKey is set.")
    }
    static var alwaysAskConfirm: String { String(localized: "factors.mac.alwaysAskConfirm", defaultValue: "This removes Touch ID unlock on this Mac.") }
    static var alwaysAskOn: String { String(localized: "factors.alwaysAskOn", defaultValue: "The key file / YubiKey is now asked at every unlock.") }
    static var alwaysAskOff: String { String(localized: "factors.mac.alwaysAskOff", defaultValue: "Touch ID can be turned on again.") }
    static var alwaysAskNeedsFactor: String { String(localized: "factors.alwaysAskNeedsFactor", defaultValue: "Add a key file or YubiKey first.") }
    static var touchIDRemoved: String { String(localized: "factors.mac.touchIDRemoved", defaultValue: "Touch ID unlock removed.") }
    static var remember: String { String(localized: "factors.mac.rememberPage", defaultValue: "Remember the key file location on this Mac") }
    static var addConfirm: String {
        String(localized: "factors.mac.addConfirm",
               defaultValue: "From now on this vault needs the master password and this factor to unlock.\n\nThe recovery phrase still opens the vault without the factor. Copies of the vault made before, and full backups (which also need their backup password), still open with the master password alone: change the master password too if you think it leaked.")
    }
    static var removeConfirm: String { String(localized: "factors.removeConfirm", defaultValue: "After this, the vault no longer needs this factor to unlock.") }
    static var addKeyFileTitle: String { String(localized: "factors.addKeyFileTitle", defaultValue: "Add a key file") }
    static var createKeyFileTitle: String { String(localized: "factors.createKeyFileTitle", defaultValue: "Create a key file") }
    static var addYubiKeyTitle: String { String(localized: "factors.addYubikeyTitle", defaultValue: "Add a YubiKey") }
    static var removeKeyFileTitle: String { String(localized: "factors.removeKeyFileTitle", defaultValue: "Remove the key file") }
    static var removeYubiKeyTitle: String { String(localized: "factors.removeYubikeyTitle", defaultValue: "Remove the YubiKey") }
    static func keyFileAdded(_ name: String) -> String { String(localized: "factors.keyFileAdded", defaultValue: "Key file \(name) added.") }
    static func keyFileCreated(_ name: String) -> String {
        String(localized: "factors.keyFileCreated", defaultValue: "Key file \(name) created and added. Keep a copy in a safe place.")
    }
    static func yubiKeyAdded(slot: Int) -> String {
        let s = String(slot)
        return String(localized: "factors.yubikeyAdded", defaultValue: "YubiKey added (slot \(s)).")
    }
    static var keyFileRemoved: String { String(localized: "factors.keyFileRemoved", defaultValue: "Key file removed.") }
    static var yubiKeyRemoved: String { String(localized: "factors.yubikeyRemoved", defaultValue: "YubiKey removed.") }
    static var backupDiffers: String {
        String(localized: "factors.backupYubikeyDiffers", defaultValue: "This YubiKey gives a different answer. Program it with the same secret as the first one.")
    }
    static var backupMatches: String {
        String(localized: "factors.backupYubikeyMatches", defaultValue: "This YubiKey gives the same answer: it also unlocks this vault.")
    }
}

/// Settings › Unlocking › Key file and YubiKey (Windows `UnlockingPage.svelte`, `FactorService`).
@MainActor @Observable
final class FactorSettingsModel {
    /// A change waiting for the master password (and the confirmation text) in its sheet.
    enum Action: Identifiable, Equatable {
        case addKeyFile(URL), createKeyFile(URL), addYubiKey(slot: Int), remove(FactorKind)
        var id: String {
            switch self {
            case .addKeyFile(let url): "add-keyfile-\(url.path)"
            case .createKeyFile(let url): "create-keyfile-\(url.path)"
            case .addYubiKey(let slot): "add-yubikey-\(slot)"
            case .remove(let kind): "remove-\(kind.rawValue)"
            }
        }
        var title: String {
            switch self {
            case .addKeyFile: FactorTexts.addKeyFileTitle
            case .createKeyFile: FactorTexts.createKeyFileTitle
            case .addYubiKey: FactorTexts.addYubiKeyTitle
            case .remove(.keyFile): FactorTexts.removeKeyFileTitle
            case .remove(.yubiKeyHMAC): FactorTexts.removeYubiKeyTitle
            }
        }
        var confirmation: String {
            if case .remove = self { return FactorTexts.removeConfirm }
            return FactorTexts.addConfirm
        }
    }

    @ObservationIgnored let service: any FactorService
    var action: Action?
    /// The page's last result line.
    var message: String?
    /// The sheet's error line (or the page's, for the backup check and the switch).
    var error: String?
    private(set) var busy = false
    /// The slot "Add YubiKey" uses (2 by default, 1 selectable).
    var slot = MacFactors.defaultSlot
    /// Bumped after every change: the factors live in `master-key.json`, not in observed state.
    private(set) var revision = 0

    init(service: any FactorService) { self.service = service }

    var specs: [FactorSpec] { _ = revision; return service.factorSpecs }
    var keyFileSet: Bool { specs.contains { $0.kind == .keyFile } }
    var yubiKeySpec: FactorSpec? { specs.first { $0.kind == .yubiKeyHMAC } }
    var alwaysAsk: Bool { _ = revision; return service.factorsAlwaysAsk }
    var rememberedName: String? { _ = revision; return service.rememberedKeyFileName }
    var prompt: YubiKeyPrompt { service.yubiKeyPrompt }

    var remember: Bool {
        get { _ = revision; return service.rememberKeyFile }
        set { service.rememberKeyFile = newValue; revision += 1 }
    }

    /// Opens the sheet for `action` (the file dialogs come first, from the view).
    func start(_ action: Action) { error = nil; message = nil; self.action = action }

    /// Runs the sheet's change; true when it is done (the sheet closes, the page shows the result).
    func run(_ action: Action, password: String) async -> Bool {
        guard !busy, !password.isEmpty else { return false }
        busy = true; error = nil
        defer { busy = false; revision += 1 }
        do {
            switch action {
            case .addKeyFile(let url): message = try await service.addKeyFile(url: url, password: password)
            case .createKeyFile(let url): message = try await service.createKeyFile(at: url, password: password)
            case .addYubiKey(let slot): message = try await service.addYubiKey(slot: slot, password: password)
            case .remove(let kind): message = try await service.removeFactor(kind, password: password)
            }
            self.action = nil
            return true
        } catch {
            self.error = MacLockModel.describe(error, now: Date(), slot: slotFor(action))
            return false
        }
    }

    func checkBackup() async {
        guard !busy else { return }
        busy = true; error = nil; message = nil
        defer { busy = false }
        do { message = try await service.checkBackupYubiKey() } catch {
            self.error = MacLockModel.describe(error, now: Date(), slot: yubiKeySpec?.slot ?? MacFactors.defaultSlot)
        }
    }

    func setAlwaysAsk(_ on: Bool) {
        error = nil
        do { message = try service.setFactorsAlwaysAsk(on) } catch {
            self.error = MacLockModel.describe(error, now: Date())
        }
        revision += 1
    }

    private func slotFor(_ action: Action) -> Int {
        if case .addYubiKey(let slot) = action { return slot }
        return yubiKeySpec?.slot ?? MacFactors.defaultSlot
    }
}

/// The rows inside Settings › Unlocking.
struct FactorSettingsRows: View {
    @Bindable var model: FactorSettingsModel
    /// Touch ID is turned on (the "Always ask" switch then confirms that it goes).
    var touchIDOn: Bool
    @Environment(\.macTheme) private var theme
    @State private var confirmAlwaysAsk = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            row(FactorTexts.keyFile, detail: model.keyFileSet ? keyFileDetail : FactorTexts.keyFileNone) {
                if model.keyFileSet {
                    Button("Remove…") { model.start(.remove(.keyFile)) }.buttonStyle(PillButtonStyle(primary: false))
                } else {
                    HStack(spacing: 8) {
                        Button(FactorTexts.addKeyFile) {
                            if let url = MacFactors.chooseKeyFile() { model.start(.addKeyFile(url)) }
                        }
                        .buttonStyle(PillButtonStyle(primary: false))
                        Button(FactorTexts.createKeyFile) {
                            if let url = MacFactors.chooseNewKeyFile() { model.start(.createKeyFile(url)) }
                        }
                        .buttonStyle(PillButtonStyle(primary: false))
                    }
                }
            }
            divider
            row(FactorTexts.yubiKey, detail: model.yubiKeySpec.map { FactorTexts.yubiKeyOn(slot: $0.slot ?? MacFactors.defaultSlot) }
                ?? FactorTexts.yubiKeyNone) {
                if model.yubiKeySpec != nil {
                    HStack(spacing: 8) {
                        Button(FactorTexts.checkBackup) { Task { await model.checkBackup() } }
                            .buttonStyle(PillButtonStyle(primary: false))
                            .help(FactorTexts.backupHint)
                        Button("Remove…") { model.start(.remove(.yubiKeyHMAC)) }.buttonStyle(PillButtonStyle(primary: false))
                    }
                } else {
                    HStack(spacing: 8) {
                        Picker(FactorTexts.slot, selection: $model.slot) {
                            Text(verbatim: "1").tag(1)
                            Text(verbatim: "2").tag(2)
                        }
                        .fixedSize()
                        Button(FactorTexts.addYubiKey) { model.start(.addYubiKey(slot: model.slot)) }
                            .buttonStyle(PillButtonStyle(primary: false))
                    }
                }
            }
            if model.yubiKeySpec == nil {
                note(FactorTexts.yubiKeySetup)
            }
            divider
            row(FactorTexts.remember, detail: model.rememberedName.map { MacFactors.keyFileChosen($0) }) {
                Toggle("", isOn: $model.remember).toggleStyle(.switch).labelsHidden()
            }
            divider
            row(FactorTexts.alwaysAskTitle, detail: FactorTexts.alwaysAskNote) {
                Toggle("", isOn: Binding(get: { model.alwaysAsk }, set: { on in
                    if on && touchIDOn && !model.specs.isEmpty { confirmAlwaysAsk = true } else { model.setAlwaysAsk(on) }
                }))
                .toggleStyle(.switch).labelsHidden()
            }
            if model.specs.isEmpty { note(FactorTexts.hint) }
            if let message = model.message { note(message) }
            if model.action == nil, let error = model.error {
                Text(error).font(.system(size: 11)).foregroundStyle(theme.danger)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 14).padding(.bottom, 8)
            }
        }
        .sheet(item: $model.action) { action in
            FactorActionSheet(model: model, action: action).macThemed()
        }
        .alert(FactorTexts.alwaysAskTitle, isPresented: $confirmAlwaysAsk) {
            Button("Cancel", role: .cancel) {}
            Button("Turn on") { model.setAlwaysAsk(true) }
        } message: {
            Text(FactorTexts.alwaysAskConfirm)
        }
    }

    private var keyFileDetail: String {
        model.rememberedName.map { FactorTexts.keyFileOn + " · " + $0 } ?? FactorTexts.keyFileOn
    }

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    private func note(_ text: String) -> some View {
        Text(text).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 14).padding(.bottom, 8)
    }

    private func row<C: View>(_ title: String, detail: String?, @ViewBuilder _ control: () -> C) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13)).foregroundStyle(theme.text)
                if let detail { Text(detail).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true) }
            }
            Spacer(minLength: 12)
            control()
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

/// The master password and the confirmation text for one factor change; "Touch your YubiKey" shows here while asked.
struct FactorActionSheet: View {
    @Bindable var model: FactorSettingsModel
    let action: FactorSettingsModel.Action
    @Environment(\.macTheme) private var theme
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text(action.title).font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            Text(action.confirmation).font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if case .addYubiKey(let slot) = action {
                Text(MacFactors.yubiKeyNeeded(slot: slot)).font(.callout).foregroundStyle(theme.text)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Enter your master password to confirm.").font(.callout).foregroundStyle(theme.textMuted)
            SecureField("Master password", text: $password).glassField().onSubmit(submit)
            YubiKeyTouchBanner(prompt: model.prompt)
            MessageLine(text: model.error)
            HStack {
                Button("Cancel") { model.prompt.cancel(); model.action = nil }
                    .buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(action: submit) {
                    if model.busy { ProgressView().controlSize(.small) } else { Text("Continue") }
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(model.busy || password.isEmpty)
            }
        }
        .disabled(model.busy && model.prompt.waitingSlot == nil)
        .padding(24).frame(width: 420)
        .background(WashBackground())
    }

    private func submit() {
        guard !model.busy, !password.isEmpty else { return }
        let typed = password
        Task {
            if !(await model.run(action, password: typed)) { password = "" }
        }
    }
}

/// "Touch your YubiKey" with Cancel, while an exchange waits for a touch (nothing otherwise).
struct YubiKeyTouchBanner: View {
    let prompt: YubiKeyPrompt
    @Environment(\.macTheme) private var theme

    var body: some View {
        if prompt.waitingSlot != nil {
            HStack(spacing: 10) {
                Image(systemName: "hand.tap").foregroundStyle(theme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(prompt.touchAgain ? MacFactors.touchAgainTitle : MacFactors.touchTitle)
                        .font(.callout.weight(.semibold)).foregroundStyle(theme.text)
                    Text(MacFactors.touchText).font(.caption).foregroundStyle(theme.textMuted)
                }
                Spacer(minLength: 8)
                Button("Cancel") { prompt.cancel() }.buttonStyle(GlassButtonStyle())
            }
            .padding(10)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
            .accessibilityElement(children: .combine)
        }
    }
}
