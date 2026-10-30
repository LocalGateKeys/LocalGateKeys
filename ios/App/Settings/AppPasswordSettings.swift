import SwiftUI
import LocalAuthentication
import AppShared

/// Task 7: the app-password rules and words, shared with Android (`AppPasswordText`).
enum AppPasswordRules {
    static let minLength = 12
    static let minScore = 3
    static var labels: [String] {
        [String(localized: "Very weak"), String(localized: "Weak"), String(localized: "Fair"), String(localized: "Strong"),
         String(localized: "Very strong")]
    }
    static var footerOff: String {
        String(localized: "Off: anyone who knows this iPhone's passcode can open LocalGateKeys. An app password closes that: the passcode alone can no longer open the vault.")
    }
    static var footerOn: String {
        String(localized: "On: LocalGateKeys opens only with the app password, your recovery phrase, or (if on) Face ID. The iPhone passcode cannot open it.")
    }
    static var phraseWarning: String {
        String(localized: "Write these 24 words down and keep them somewhere safe. They are the only way back in if you forget the app password. No password and no phrase means no way in: nobody, including us, can open the vault for you.")
    }

    /// The desktop sync/backup password rule (12+ characters, `estimate_strength` score 3+, both entries equal).
    static func problem(_ password: String, confirm: String) -> String? {
        if password.unicodeScalars.count < minLength { return String(localized: "Use at least \(minLength) characters.") }
        if PasswordStrength.estimate(password).score < minScore { return String(localized: "Too easy to guess. Add more words or characters.") }
        if password != confirm { return String(localized: "The two passwords do not match.") }
        return nil
    }

    static func label(_ password: String) -> String { labels[min(max(PasswordStrength.estimate(password).score, 0), 4)] }

    /// Three distinct word positions (0-based, ascending), without modulo bias.
    static func confirmPositions(random: any RandomSource) -> [Int] {
        var picked = Set<Int>()
        while picked.count < 3 {
            let b = Int(random.bytes(count: 1)[0])
            if b < 240 { picked.insert(b % BIP39.wordCount) }
        }
        return picked.sorted()
    }

    static func confirms(phrase: String, positions: [Int], typed: [String]) -> Bool {
        let words = phrase.split(separator: " ").map(String.init)
        guard positions.count == typed.count else { return false }
        return zip(positions, typed).allSatisfy { words[$0] == $1.trimmingCharacters(in: .whitespaces).lowercased() }
    }
}

/// Turns the app password on and off, changes it and sets the Face ID shortcut, while the vault is unlocked.
/// `keychain` is the unlocked app's (`AppLockModel.keychain`): it reads the local key and re-protects the sync slots.
@MainActor
struct AppPasswordController {
    let store: AppPasswordStore
    let keychain: any KeychainVault
    var journal: any AppPasswordReprotectJournal = KeychainReprotectJournal()

    private func localKey() throws -> [UInt8] {
        guard let k = try keychain.read(.localKey) else { throw LocalStoreError.noLocalKey }
        return k
    }

    func prepare(password: String) async throws -> (file: MasterKeyFile, phrase: String) {
        let key = try localKey()
        let store = self.store
        return try await Task.detached(priority: .userInitiated) {
            try store.prepare(localKey: key, password: password, random: SystemRandomSource())
        }.value
    }

    /// After the phrase was confirmed: the file (password mode from here on), the Face ID item if asked, the sync
    /// slots without `.userPresence`, and last the passcode item of the local key is deleted. Never over a file that
    /// is already there (that would replace the phrase the person wrote down). A crash or error after the file was
    /// written is finished by the next unlock (`SystemUnlocker`: `repairAtUnlock` and the passcode item delete).
    func commit(_ file: MasterKeyFile, faceID: Bool) throws {
        guard !store.isOn else { throw AppPasswordError.alreadyOn }
        let key = try localKey()
        try AppPasswordKeychainMigration.begin(journal: journal)
        try store.write(file)
        if faceID { try? store.biometric.store(key) }
        try AppPasswordKeychainMigration.reprotect(keychain, journal: journal)
        try SystemKeychainVault().delete(.localKey)
    }

    func change(current: String, new: String) async throws {
        let key = try localKey()
        let store = self.store
        try await Task.detached(priority: .userInitiated) {
            var check = try store.open(password: current)
            for i in check.indices { check[i] = 0 }
            try store.write(try store.withNewPassword(try store.readFile(), localKey: key, password: new, random: SystemRandomSource()))
        }.value
    }

    /// The current password, then the local key goes back into the Keychain with `.userPresence`, the shortcut and
    /// the file are removed, and the sync slots get `.userPresence` again.
    func turnOff(current: String) async throws {
        let store = self.store
        let key = try await Task.detached(priority: .userInitiated) { try store.open(password: current) }.value
        try AppPasswordKeychainMigration.begin(journal: journal)
        try SystemKeychainVault().addPasscodeProtected(.localKey, key)
        store.removeAll()
        // A crash before this finishes: the next (passcode) unlock re-runs it (`repairAtUnlock`).
        try AppPasswordKeychainMigration.reprotect(keychain, journal: journal)
    }

    func setFaceID(_ on: Bool) throws {
        if on { try store.biometric.store(try localKey()) } else { try store.biometric.remove() }
    }

    static var faceIDAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
}

/// Settings › Security › App password.
struct AppPasswordSection: View {
    let lock: AppLockModel
    @State private var on = AppPasswordStore.shared()?.isOn ?? false
    @State private var faceID = AppPasswordStore.shared()?.biometricOn ?? false
    /// The setup sheet, presented by SettingsView (see there).
    @Binding var showSetup: Bool
    @State private var dialog: String?   // "off" or "change"
    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var message: String?

    private var controller: AppPasswordController? {
        guard let store = AppPasswordStore.shared(), let kc = lock.keychain else { return nil }
        return AppPasswordController(store: store, keychain: kc)
    }

    private func reload() {
        on = AppPasswordStore.shared()?.isOn ?? false
        faceID = AppPasswordStore.shared()?.biometricOn ?? false
    }

    var body: some View {
        Section {
            Toggle("Use an app password", isOn: Binding(get: { on }, set: { want in
                reload()   // the file decides: a half-done turn-on must not be turned on again (a new phrase)
                if want && !on { showSetup = true } else if !want && on { dialog = "off" }
            }))
            if on {
                if AppPasswordController.faceIDAvailable || faceID {
                    Toggle("Unlock with Face ID", isOn: Binding(get: { faceID }, set: { want in
                        do { try controller?.setFaceID(want); message = nil } catch { message = AppLockModel.message(for: error) }
                        reload()
                    }))
                }
                Button("Change app password") { dialog = "change" }.foregroundStyle(Palette.accentText)
            }
        } header: {
            Text("App password")
        } footer: {
            Text(message ?? (on ? AppPasswordRules.footerOn : AppPasswordRules.footerOff))
        }
        .listRowBackground(Palette.groupSurface)
        .onChange(of: showSetup) { _, open in if !open { reload() } }
        .alert(dialog == "off" ? String(localized: "Turn off the app password?") : String(localized: "Change app password"), isPresented: Binding(
            get: { dialog != nil }, set: { if !$0 { dialog = nil; current = ""; new = ""; confirm = "" } })) {
            SecureField("Current app password", text: $current)
            if dialog == "change" {
                SecureField("New app password", text: $new)
                SecureField("Confirm new app password", text: $confirm)
            }
            Button(dialog == "off" ? String(localized: "Turn off") : String(localized: "Change")) { submit() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(dialog == "off" ? String(localized: "Afterwards the iPhone passcode opens LocalGateKeys again.") : String(localized: "Your recovery phrase stays the same."))
        }
    }

    private func submit() {
        let (kind, cur, n, c) = (dialog, current, new, confirm)
        current = ""; new = ""; confirm = ""
        guard let controller else { return }
        if kind == "change", let p = AppPasswordRules.problem(n, confirm: c) { message = p; return }
        Task {
            do {
                if kind == "off" { try await controller.turnOff(current: cur); message = nil }
                else { try await controller.change(current: cur, new: n); message = String(localized: "App password changed.") }
            } catch {
                message = AppLockModel.message(for: error) ?? String(localized: "Cancelled.")
            }
            reload()
        }
    }
}

/// Turning it on: the password twice with the strength check, the 24 words, then three of them typed back.
/// Nothing changes on disk until the last step.
struct AppPasswordSetupView: View {
    let controller: AppPasswordController
    /// The app locks once the password is on: the open session still holds the old Keychain view.
    let onTurnedOn: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var step = 0
    @State private var password = ""
    @State private var confirm = ""
    @State private var faceID = AppPasswordController.faceIDAvailable
    @State private var prepared: (file: MasterKeyFile, phrase: String)?
    @State private var positions = AppPasswordRules.confirmPositions(random: SystemRandomSource())
    @State private var typed = ["", "", ""]
    @State private var problem: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                switch step {
                case 0:
                    Section {
                        SecureField("App password", text: $password).textContentType(.newPassword)
                        SecureField("Confirm app password", text: $confirm).textContentType(.newPassword)
                        if !password.isEmpty { LabeledContent("Strength", value: AppPasswordRules.label(password)) }
                        if AppPasswordController.faceIDAvailable { Toggle("Unlock with Face ID", isOn: $faceID) }
                    } footer: {
                        Text("From now on this password, not the iPhone passcode, opens LocalGateKeys.")
                    }
                    Button("Continue") { prepare() }.disabled(busy)
                case 1:
                    Section {
                        Text(AppPasswordRules.phraseWarning).foregroundStyle(Palette.danger)
                        let words = prepared?.phrase.split(separator: " ").map(String.init) ?? []
                        ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                            Text("\(i + 1). \(w)").font(.body.monospaced())
                        }
                    }
                    Button("I wrote them down") { step = 2 }
                default:
                    Section {
                        ForEach(0..<3, id: \.self) { i in
                            TextField("Word \(positions[i] + 1)", text: $typed[i])
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                        }
                    } footer: {
                        Text("Type these words from your phrase to confirm you saved it.")
                    }
                    Button("Turn on app password") { commit() }.disabled(busy)
                }
                if busy { ProgressView() }
                if let problem { Text(problem).foregroundStyle(Palette.danger) }
            }
            .navigationTitle("App password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { prepared = nil; dismiss() }.disabled(busy) } }
        }
        .interactiveDismissDisabled(busy || step > 0)
    }

    private func prepare() {
        if let p = AppPasswordRules.problem(password, confirm: confirm) { problem = p; return }
        busy = true; problem = nil
        let pw = password
        Task {
            do {
                prepared = try await controller.prepare(password: pw)
                password = ""; confirm = ""
                step = 1
            } catch {
                problem = AppLockModel.message(for: error) ?? String(localized: "Could not prepare the app password.")
            }
            busy = false
        }
    }

    private func commit() {
        guard let prepared else { return }
        guard AppPasswordRules.confirms(phrase: prepared.phrase, positions: positions, typed: typed) else {
            problem = String(localized: "Those words do not match your phrase. Check the numbers and try again.")
            return
        }
        do {
            try controller.commit(prepared.file, faceID: faceID)
            self.prepared = nil
            dismiss()
            onTurnedOn()
        } catch {
            if controller.store.isOn {
                // The file was written: the password is on (the phrase shown is the one that works) and the next
                // unlock finishes the rest. Never offer to turn it on again, which would replace the phrase.
                self.prepared = nil
                dismiss()
                onTurnedOn()
            } else {
                problem = AppLockModel.message(for: error) ?? String(localized: "Could not turn on the app password.")
            }
        }
    }
}
