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
        DeviceText.isPad ? String(localized: "ipad.appPasswordSettings.offAnyoneWhoKnows", defaultValue: "Off: anyone who knows this iPad's passcode can open LocalGateKeys. An app password closes that: the passcode alone can no longer open the vault.") : String(localized: "Off: anyone who knows this iPhone's passcode can open LocalGateKeys. An app password closes that: the passcode alone can no longer open the vault.")
    }
    static var footerOn: String {
        DeviceText.isPad ? String(localized: "ipad.appPasswordSettings.localgatekeysOpensOnlyWith", defaultValue: "On: LocalGateKeys opens only with the app password, your recovery phrase, or (if on) Face ID. The iPad passcode cannot open it.") : String(localized: "On: LocalGateKeys opens only with the app password, your recovery phrase, or (if on) Face ID. The iPhone passcode cannot open it.")
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
    /// Task 8: the key-file bookmark and the YubiKey over NFC (nil: no factors can be supplied or added).
    var factors: (any PhoneFactorSourcing)? = nil
    var settings: AppSettings = .shared
    /// Sub-plan 08: the open vault is the duress password's second vault (`AppLockModel.secondSession`).
    var secondSession = false
    var duress: PhoneDuress? = PhoneDuress.shared()

    /// In a duress session the real app password's record is never touched: turning it off, the Face ID shortcut
    /// and the key file / YubiKey end with "not available right now" (Android parity).
    private func refuseInSecondSession() throws {
        if secondSession { throw DuressError("unavailable") }
    }

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

    /// A new password (Task 8: the factors stay; a YubiKey answers a new challenge, one more tap). Verify before
    /// commit: the new file must open again before it replaces the old one (`AppPasswordStore.rewrap`).
    /// `keyFile`: the key file picked for this change (nil: the remembered one).
    /// Sub-plan 08 (Ruling T5a-b): in a duress session only the second vault's password changes, throttled like
    /// this one; the real change refuses the duress password and anything one edit from it.
    func change(current: String, new: String, keyFile: URL? = nil) async throws {
        let routing = DuressRouting(inDuressSession: { secondSession }, duress: duress, throttle: store)
        try await routing.changePassword(localKey: { try localKey() }, current: current, new: new) {
            let input = try await factorInput(keyFile: keyFile)
            let store = self.store, duress = self.duress
            try await Task.detached(priority: .userInitiated) {
                var opened = try await store.openKeepingFactors(password: current, factors: input)
                defer { opened.clear() }
                try duress?.checkNewPassword(realKey: opened.key, newPassword: new, decoySession: false)
                try await store.rewrap(opened, password: new, random: SystemRandomSource())
            }.value
            rememberPicked(keyFile)
        }
    }

    /// The current password (and its factors), then the local key goes back into the Keychain with `.userPresence`,
    /// the shortcut and the file are removed, and the sync slots get `.userPresence` again. The key file is
    /// forgotten: without the app password there are no factors.
    func turnOff(current: String, keyFile: URL? = nil) async throws {
        try refuseInSecondSession()
        let input = try await factorInput(keyFile: keyFile)
        let store = self.store
        let key = try await Task.detached(priority: .userInitiated) {
            try await store.open(password: current, factors: input)
        }.value
        factors?.forgetKeyFile()
        // The duress password is a second app password: it goes with the app password (sub-plan 08).
        duress?.eraseAll()
        try AppPasswordKeychainMigration.begin(journal: journal)
        try SystemKeychainVault().addPasscodeProtected(.localKey, key)
        store.removeAll()
        // A crash before this finishes: the next (passcode) unlock re-runs it (`repairAtUnlock`).
        try AppPasswordKeychainMigration.reprotect(keychain, journal: journal)
    }

    /// The owner check with the app password on (`AppPasswordGate`, audit 2026-11-10): `current` (with today's key
    /// file and YubiKey) must open to the open vault's local key, through the unlock's wrong-try delay and count. In a
    /// duress session it is checked against the second vault only, as for the duress setup (no oracle on the real one).
    func verify(current: String) async throws {
        var session = try localKey()
        defer { for i in session.indices { session[i] = 0 } }
        // The task gets its own buffer in a box (not a copy-on-write share of `session`), zeroed here once it ends.
        let store = self.store, key = KeyBytes(Array(session))
        defer { key.zero() }
        if secondSession {
            guard let duress else { throw AppPasswordError.wrongPassword }
            try await Task.detached(priority: .userInitiated) {
                let wait = store.waitSeconds()
                if wait > 0 { throw AppPasswordError.wait(seconds: wait) }
                var opened = duress.tryOpen(password: current) ?? []
                defer { for i in opened.indices { opened[i] = 0 } }
                guard !opened.isEmpty, Envelope.same(opened, key.bytes) else { store.noteWrongTry(); throw AppPasswordError.wrongPassword }
                store.clearFailures()
            }.value
            return
        }
        let input = try await factorInput(keyFile: nil)
        try await Task.detached(priority: .userInitiated) {
            var opened = try await store.open(password: current, factors: input)
            defer { for i in opened.indices { opened[i] = 0 } }
            guard Envelope.same(opened, key.bytes) else { throw AppPasswordError.wrongPassword }
        }.value
    }

    func setFaceID(_ on: Bool) throws {
        try refuseInSecondSession()
        if on, settings.factorsAlwaysAsk, store.hasFactors { throw FactorMessageError(PhoneFactors.faceIDOff) }
        if on { try store.biometric.store(try localKey()) } else { try store.biometric.remove() }
    }

    // MARK: Task 8: key file and YubiKey (Settings › App password, only while it is on)

    var specs: [FactorSpec] { store.factorSpecs }
    var keyFileSpec: FactorSpec? { specs.first { $0.kind == .keyFile } }

    /// True when today's key file must be picked first (it is set and this iPhone does not remember it).
    var needsKeyFilePick: Bool {
        guard let spec = keyFileSpec else { return false }
        return factors?.rememberedKeyFile(check: spec.check) == nil
    }

    /// Today's factors: the picked (else remembered) key file's bytes and the NFC responder.
    private func factorInput(keyFile picked: URL?) async throws -> FactorSecrets {
        var input = FactorSecrets()
        guard let factors else { return input }
        let specs = self.specs
        if let spec = specs.first(where: { $0.kind == .keyFile }),
           let url = picked ?? factors.rememberedKeyFile(check: spec.check)?.url {
            input.keyFile = try await factors.readKeyFile(url)
        }
        if let spec = specs.first(where: { $0.kind == .yubiKeyHMAC }) {
            input.yubiKey = factors.yubiKey(slot: spec.slot ?? PhoneFactors.defaultSlot, confirming: false)
        }
        return input
    }

    /// A key file picked for a change is remembered once the change succeeded.
    private func rememberPicked(_ url: URL?) {
        guard let url, let spec = keyFileSpec else { return }
        factors?.rememberKeyFile(url, check: spec.check)
    }

    /// Adds the key file `file` (opened in place by the picker; read within `KeyFile.maxBytes`, never copied). The
    /// password and today's factors open the file first; a YubiKey that stays answers a new challenge.
    func addKeyFile(current: String, file: URL, remember: Bool, keyFile: URL? = nil) async throws {
        try refuseInSecondSession()
        guard keyFileSpec == nil else { throw PhoneFactors.alreadySet }
        guard let factors else { throw FactorError.required([.keyFile]) }
        let input = try await factorInput(keyFile: keyFile)
        let data = try await factors.readKeyFile(file)
        let store = self.store
        let check = try await Task.detached(priority: .userInitiated) { () async throws -> String in
            var opened = try await store.openKeepingFactors(password: current, factors: input)
            defer { opened.clear() }
            var enrolled = try CompositeKey.enrolKeyFile(data)
            defer { for i in enrolled.secret.indices { enrolled.secret[i] = 0 } }
            try await store.rewrap(opened, password: current, added: ([enrolled.spec], [enrolled.secret]), random: SystemRandomSource())
            return enrolled.spec.check
        }.value
        if remember { factors.rememberKeyFile(file, check: check) } else { factors.forgetKeyFile() }
    }

    /// Adds the YubiKey answering from `slot` (two taps that must agree, then the wrapper is rewritten).
    func addYubiKey(current: String, slot: Int = PhoneFactors.defaultSlot, keyFile: URL? = nil) async throws {
        try refuseInSecondSession()
        guard !specs.contains(where: { $0.kind == .yubiKeyHMAC }) else { throw PhoneFactors.alreadySet }
        guard let factors else { throw FactorError.required([.yubiKeyHMAC]) }
        let input = try await factorInput(keyFile: keyFile)
        let respond = factors.yubiKey(slot: slot, confirming: true)
        let store = self.store
        try await Task.detached(priority: .userInitiated) {
            var opened = try await store.openKeepingFactors(password: current, factors: input)
            defer { opened.clear() }
            var enrolled = try await CompositeKey.enrolYubiKey(slot: slot, random: SystemRandomSource(), respond: respond)
            defer { for i in enrolled.secret.indices { enrolled.secret[i] = 0 } }
            try await store.rewrap(opened, password: current, added: ([enrolled.spec], [enrolled.secret]), random: SystemRandomSource())
        }.value
        rememberPicked(keyFile)
    }

    /// Removes the key file or the YubiKey; with none left the file is version 1 again.
    func removeFactor(_ kind: FactorKind, current: String, keyFile: URL? = nil) async throws {
        try refuseInSecondSession()
        guard specs.contains(where: { $0.kind == kind }) else { throw PhoneFactors.notSet }
        let input = try await factorInput(keyFile: keyFile)
        let store = self.store
        try await Task.detached(priority: .userInitiated) {
            var opened = try await store.openKeepingFactors(password: current, factors: input)
            defer { opened.clear() }
            try await store.rewrap(opened, password: current, dropping: kind, random: SystemRandomSource())
        }.value
        if kind == .keyFile { factors?.forgetKeyFile() } else { rememberPicked(keyFile) }
    }

    /// "Always ask for the key file / YubiKey": on deletes the Face ID shortcut item (less access, no password
    /// needed); the unlock enforces it too (`SystemUnlocker`).
    func setAlwaysAsk(_ on: Bool) throws {
        try refuseInSecondSession()
        if on, !store.hasFactors { throw FactorMessageError(PhoneFactors.alwaysAskNeedsFactor) }
        settings.factorsAlwaysAsk = on
        if on { try store.biometric.remove() }
    }

    // MARK: sub-plan 08: the duress password (Settings › App password › Duress password)

    /// What Settings shows: inside a duress session it looks not set up.
    func duressStatus() -> (on: Bool, hours: Int) {
        guard !secondSession, let duress, duress.configured, var key = try? localKey() else { return (false, PhoneDuress.defaultHours) }
        defer { for i in key.indices { key[i] = 0 } }
        return (true, duress.realHours(realKey: key) ?? PhoneDuress.defaultHours)
    }

    /// Sets up the duress password. The current app password is checked first (in a duress session against the
    /// second vault, counted like any wrong try, never against the real one); there every check runs and then the
    /// plain "couldn't save" ends it with nothing written. `real` is the open (real) vault's snapshot the sample
    /// items take the user name from.
    func setUpDuress(current: String, password: String, confirm: String, hours: Int, isPro: Bool,
                     real: StoreSnapshot) async throws {
        guard isPro else { throw DuressError("pro") }
        guard store.isOn else { throw DuressError("needs_password") }
        guard password.utf8.elementsEqual(confirm.utf8) else { throw DuressError("mismatch") }
        guard let duress else { throw DuressError("generic") }
        var session = try localKey()
        defer { for i in session.indices { session[i] = 0 } }
        let store = self.store, key = session
        if secondSession {
            try await Task.detached(priority: .userInitiated) {
                let wait = store.waitSeconds()
                if wait > 0 { throw AppPasswordError.wait(seconds: wait) }
                var opened = duress.tryOpen(password: current) ?? []
                defer { for i in opened.indices { opened[i] = 0 } }
                guard !opened.isEmpty, Envelope.same(opened, key) else { store.noteWrongTry(); throw AppPasswordError.wrongPassword }
                store.clearFailures()
                try duress.setup(realKey: key, appPassword: current, duressPassword: password, hours: hours,
                                 decoySession: true) { _ in }
            }.value
            return
        }
        let input = try await factorInput(keyFile: nil)
        try await Task.detached(priority: .userInitiated) {
            var opened = try await store.openKeepingFactors(password: current, factors: input)
            defer { opened.clear() }
            try duress.setup(realKey: opened.key, appPassword: current, duressPassword: password, hours: hours,
                             decoySession: false) { store in
                try DuressSamples.seed(store, real: real, random: SystemRandomSource(), now: Int64(Date().timeIntervalSince1970))
            }
        }.value
    }

    /// Removes the duress password and its vault (in a duress session: the plain "couldn't save", nothing removed).
    func removeDuress() throws {
        guard let duress else { throw DuressError("generic") }
        try duress.remove(decoySession: secondSession)
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
    /// Task 8: today's key file, picked before a change or turn-off when this iPhone does not remember it.
    @State private var keyFile: URL?
    @State private var pickingKeyFile = false
    @State private var afterPick: String?

    private var controller: AppPasswordController? {
        guard let store = AppPasswordStore.shared(), let kc = lock.keychain else { return nil }
        return AppPasswordController(store: store, keychain: kc, factors: lock.factors, secondSession: lock.secondSession)
    }

    /// Opens the "off" or "change" dialog, after the key-file picker when today's key file is needed and not
    /// remembered.
    private func start(_ kind: String) {
        if controller?.needsKeyFilePick == true {
            afterPick = kind
            pickingKeyFile = true
        } else {
            dialog = kind
        }
    }

    private func reload() {
        on = AppPasswordStore.shared()?.isOn ?? false
        faceID = AppPasswordStore.shared()?.biometricOn ?? false
    }

    var body: some View {
        mainSection
        AppPasswordFactorSection(lock: lock, on: on, changed: reload)
    }

    private var mainSection: some View {
        Section {
            Toggle("Use an app password", isOn: Binding(get: { on }, set: { want in
                reload()   // the file decides: a half-done turn-on must not be turned on again (a new phrase)
                if want && !on { showSetup = true } else if !want && on { start("off") }
            }))
            if on {
                if AppPasswordController.faceIDAvailable || faceID {
                    Toggle("Unlock with Face ID", isOn: Binding(get: { faceID }, set: { want in
                        do { try controller?.setFaceID(want); message = nil } catch { message = AppLockModel.message(for: error) }
                        reload()
                    }))
                }
                Button("Change app password") { start("change") }.foregroundStyle(Palette.accentText)
                // The phrase is not kept anywhere after setup, so this kit has blank phrase boxes.
                Button("Print emergency kit (phrase boxes blank)") { EmergencyKitDocument.print(EmergencyKitDocument.phoneFacts(), words: nil) }
                    .foregroundStyle(Palette.accentText)
            }
        } header: {
            Text("App password")
        } footer: {
            Text(message ?? (on ? AppPasswordRules.footerOn : AppPasswordRules.footerOff))
        }
        .listRowBackground(Palette.groupSurface)
        .onChange(of: showSetup) { _, open in if !open { reload() } }
        .sheet(isPresented: $pickingKeyFile, onDismiss: {
            if keyFile != nil, let next = afterPick { dialog = next }
            afterPick = nil
        }) {
            KeyFilePicker { url in keyFile = url }.ignoresSafeArea()
        }
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
            Text(dialog == "off" ? (DeviceText.isPad ? String(localized: "ipad.appPasswordSettings.afterwardsPasscodeOpensLocalgatekeys", defaultValue: "Afterwards the iPad passcode opens LocalGateKeys again.") : String(localized: "Afterwards the iPhone passcode opens LocalGateKeys again.")) : String(localized: "Your recovery phrase stays the same."))
        }
    }

    private func submit() {
        let (kind, cur, n, c, picked) = (dialog, current, new, confirm, keyFile)
        current = ""; new = ""; confirm = ""; keyFile = nil
        guard let controller else { return }
        if kind == "change", let p = AppPasswordRules.problem(n, confirm: c) { message = p; return }
        Task {
            do {
                if kind == "off" { try await controller.turnOff(current: cur, keyFile: picked); message = nil }
                else { try await controller.change(current: cur, new: n, keyFile: picked); message = String(localized: "App password changed.") }
            } catch {
                message = AppLockModel.message(for: error) ?? String(localized: "Cancelled.")
            }
            reload()
        }
    }
}

/// Task 8: Settings › App password › Key file and YubiKey, only while the app password is on (design §4.6/§4.7).
/// Every change asks for the current app password (and today's factors) and is checked before it is written.
struct AppPasswordFactorSection: View {
    let lock: AppLockModel
    let on: Bool
    /// The parent reloads its Face ID switch (Always ask removes the shortcut).
    let changed: @MainActor () -> Void

    enum Action: String, Identifiable { case addKeyFile, addYubiKey, removeKeyFile, removeYubiKey; var id: String { rawValue } }
    enum Pick: String, Identifiable { case newKeyFile, todaysKeyFile; var id: String { rawValue } }

    @State private var revision = 0
    @State private var action: Action?
    @State private var picking: Pick?
    @State private var afterPick: Action?
    /// The key file being added, and today's key file when it must be picked for a change.
    @State private var newKeyFile: URL?
    @State private var todaysKeyFile: URL?
    @State private var dontRemember = false
    @State private var current = ""
    @State private var message: String?
    @State private var busy = false

    private var controller: AppPasswordController? {
        guard let store = AppPasswordStore.shared(), let kc = lock.keychain else { return nil }
        return AppPasswordController(store: store, keychain: kc, factors: lock.factors, secondSession: lock.secondSession)
    }

    private var specs: [FactorSpec] { _ = revision; return controller?.specs ?? [] }

    var body: some View {
        Section {
            if !on {
                Text(PhoneFactors.needsAppPassword).foregroundStyle(Palette.secondaryText)
            } else {
                let keySpec = specs.first { $0.kind == .keyFile }
                let yubiSpec = specs.first { $0.kind == .yubiKeyHMAC }
                if keySpec != nil {
                    LabeledContent(PhoneFactors.keyFile, value: PhoneFactors.keyFileOn)
                    Button(PhoneFactors.removeKeyFileTitle, role: .destructive) { begin(.removeKeyFile) }.disabled(busy)
                } else {
                    Button(PhoneFactors.addKeyFile) {
                        afterPick = .addKeyFile
                        picking = .newKeyFile
                    }
                    .foregroundStyle(Palette.accentText).disabled(busy)
                    Toggle(PhoneFactors.dontRemember, isOn: $dontRemember)
                }
                if let yubiSpec {
                    LabeledContent(PhoneFactors.yubiKey, value: PhoneFactors.yubiKeyOn(slot: yubiSpec.slot ?? PhoneFactors.defaultSlot))
                    Button(PhoneFactors.removeYubiKeyTitle, role: .destructive) { begin(.removeYubiKey) }.disabled(busy)
                } else {
                    Button(PhoneFactors.addYubiKey) { begin(.addYubiKey) }
                        .foregroundStyle(Palette.accentText).disabled(busy || !YubiKeyNFCReader.isAvailable)
                }
                if !specs.isEmpty {
                    Toggle(PhoneFactors.alwaysAskTitle, isOn: Binding(get: { _ = revision; return AppSettings.shared.factorsAlwaysAsk },
                                                                      set: { setAlwaysAsk($0) }))
                }
                if busy { ProgressView() }
            }
        } header: {
            Text(PhoneFactors.section)
        } footer: {
            if on { Text(message ?? (PhoneFactors.hint + "\n\n" + PhoneFactors.yubiKeySetup + "\n\n" + PhoneFactors.alwaysAskNote)) }
        }
        .listRowBackground(Palette.groupSurface)
        .sheet(item: $picking, onDismiss: pickDismissed) { pick in
            KeyFilePicker { url in
                if pick == .newKeyFile { newKeyFile = url } else { todaysKeyFile = url }
            }
            .ignoresSafeArea()
        }
        .alert(title(action), isPresented: Binding(get: { action != nil }, set: { if !$0 { action = nil; current = "" } }),
               presenting: action) { a in
            SecureField("Current app password", text: $current)
            Button(a == .addKeyFile || a == .addYubiKey ? String(localized: "Add") : String(localized: "Remove"),
                   role: a == .addKeyFile || a == .addYubiKey ? nil : .destructive) { run(a) }
            Button("Cancel", role: .cancel) { newKeyFile = nil; todaysKeyFile = nil }
        } message: { a in
            Text(a == .addKeyFile || a == .addYubiKey ? PhoneFactors.addConfirm : PhoneFactors.removeConfirm)
        }
    }

    private func title(_ a: Action?) -> String {
        switch a {
        case .addKeyFile: return PhoneFactors.addKeyFileTitle
        case .addYubiKey: return PhoneFactors.addYubiKeyTitle
        case .removeKeyFile: return PhoneFactors.removeKeyFileTitle
        case .removeYubiKey: return PhoneFactors.removeYubiKeyTitle
        case nil: return ""
        }
    }

    /// The password dialog for `a`, after the picker when today's key file is needed and not remembered.
    private func begin(_ a: Action) {
        if a != .addKeyFile, todaysKeyFile == nil, controller?.needsKeyFilePick == true {
            afterPick = a
            picking = .todaysKeyFile
        } else {
            action = a
        }
    }

    private func pickDismissed() {
        guard let next = afterPick else { return }
        afterPick = nil
        if next == .addKeyFile {
            guard newKeyFile != nil else { return }
        } else if todaysKeyFile == nil {
            return
        }
        action = next
    }

    private func run(_ a: Action) {
        let cur = current, picked = todaysKeyFile, file = newKeyFile, remember = !dontRemember
        current = ""
        guard let controller else { return }
        busy = true; message = nil
        Task {
            do {
                switch a {
                case .addKeyFile:
                    guard let file else { break }
                    try await controller.addKeyFile(current: cur, file: file, remember: remember, keyFile: picked)
                    message = PhoneFactors.keyFileAdded(file.lastPathComponent)
                case .addYubiKey:
                    try await controller.addYubiKey(current: cur, keyFile: picked)
                    message = PhoneFactors.yubiKeyAdded(slot: PhoneFactors.defaultSlot)
                case .removeKeyFile:
                    try await controller.removeFactor(.keyFile, current: cur, keyFile: picked)
                    message = PhoneFactors.keyFileRemoved
                case .removeYubiKey:
                    try await controller.removeFactor(.yubiKeyHMAC, current: cur, keyFile: picked)
                    message = PhoneFactors.yubiKeyRemoved
                }
            } catch {
                message = AppLockModel.message(for: error) ?? String(localized: "Cancelled.")
            }
            busy = false; newKeyFile = nil; todaysKeyFile = nil
            revision += 1
            changed()
        }
    }

    private func setAlwaysAsk(_ on: Bool) {
        do {
            try controller?.setAlwaysAsk(on)
            message = on ? String(localized: "factors.alwaysAskOn", defaultValue: "The key file / YubiKey is now asked at every unlock.") : nil
        } catch {
            message = AppLockModel.message(for: error) ?? String(localized: "Cancelled.")
        }
        revision += 1
        changed()
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
                        Text(DeviceText.isPad ? String(localized: "ipad.appPasswordSettings.fromNowPasswordNot", defaultValue: "From now on this password, not the iPad passcode, opens LocalGateKeys.") : String(localized: "From now on this password, not the iPhone passcode, opens LocalGateKeys."))
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
                    // The words go straight to the print job; nothing is stored, and the print sheet drops them.
                    Button("Print emergency kit with this phrase") {
                        EmergencyKitDocument.print(EmergencyKitDocument.phoneFacts(),
                                                   words: prepared?.phrase.split(separator: " ").map(String.init))
                    }
                    .foregroundStyle(Palette.accentText)
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

/// Key bytes handed to a detached task: one buffer, shared by reference, zeroed in place by `zero()`.
private final class KeyBytes: @unchecked Sendable {
    private(set) var bytes: [UInt8]
    init(_ bytes: [UInt8]) { self.bytes = bytes }
    func zero() { for i in bytes.indices { bytes[i] = 0 } }
}
