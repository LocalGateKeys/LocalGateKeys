import SwiftUI
import Observation
import AppSharedMac

/// The one gate for logins with `policy.require_master_password` (Windows `secrets.py` with
/// `allow_hello=not strict`): every release of such a login's secrets — copying the username, password or
/// one-time code, showing the password, code or notes, opening the editor — asks for the master password
/// first. Never Touch ID, no grace period: each release asks again. The vault's unlock throttle applies, and a
/// cancelled or failed prompt releases nothing. Other items pass straight through.
@MainActor @Observable
final class StrictItemGate {
    /// Strict: master password every time. Routine (Windows `reauthenticate(allow_hello=True)`): Touch ID when
    /// turned on, else the master password, then a 120 s grace for this unlock session.
    enum Level: Equatable { case strict, routine }

    struct Request: Identifiable {
        let id = UUID()
        let title: String
        /// "Copy username", "Show notes", …
        let action: String
        let level: Level
        let offersTouchID: Bool
        let perform: () -> Void
    }

    /// Windows `ROUTINE_REAUTH_GRACE_SECONDS`.
    static let routineGraceSeconds: TimeInterval = 120

    /// The prompt on screen, if any.
    private(set) var pending: Request?
    private(set) var message: String?
    private(set) var busy = false
    /// Whether the prompt on screen may use Touch ID (never for strict logins).
    var offersTouchID: Bool { pending?.offersTouchID ?? false }

    @ObservationIgnored private let passwords: (any MasterPasswordService)?
    @ObservationIgnored private let now: () -> Date
    /// (session generation, expiry) of the routine grace.
    @ObservationIgnored private var grace: (generation: Int, until: Date)?

    init(passwords: (any MasterPasswordService)?, now: @escaping () -> Date = Date.init) {
        self.passwords = passwords; self.now = now
    }

    static func isStrict(_ item: VaultItem) -> Bool {
        item.record["policy"]?.objectValue?["require_master_password"] == .bool(true)
    }

    /// Runs `perform` now for an ordinary item; for a strict one, only after the master password is confirmed.
    func release(_ item: VaultItem, action: String, perform: @escaping () -> Void) {
        guard Self.isStrict(item) else { perform(); return }
        ask(item, action: action, level: .strict, perform: perform)
    }

    /// A routine secret (password reveal/copy, recovery codes, hidden fields, password history): strict logins
    /// as `release`; others ask once (Touch ID or master password) and then not again for 120 s.
    func releaseRoutine(_ item: VaultItem, action: String, perform: @escaping () -> Void) {
        if Self.isStrict(item) { ask(item, action: action, level: .strict, perform: perform); return }
        if graceValid { perform(); return }
        ask(item, action: action, level: .routine, perform: perform)
    }

    /// Asks for the master password (never Touch ID, no grace) before an action that is not about one item,
    /// such as writing the vault's secrets to a file (Windows export: `reauthenticate(allow_hello=False)`).
    /// Refused (false) while another prompt is open: that prompt is never silently replaced.
    @discardableResult
    func confirmMasterPassword(title: String, action: String, perform: @escaping () -> Void) -> Bool {
        guard pending == nil else { return false }
        message = nil
        pending = Request(title: title, action: action, level: .strict, offersTouchID: false, perform: perform)
        return true
    }

    private var graceValid: Bool {
        guard let grace, let passwords else { return false }
        return grace.generation == passwords.sessionGeneration && now() < grace.until
    }

    private func ask(_ item: VaultItem, action: String, level: Level, perform: @escaping () -> Void) {
        message = nil
        pending = Request(title: item.title.isEmpty ? item.kindLabel : item.title, action: action, level: level,
                          offersTouchID: level == .routine && (passwords?.routineTouchIDEnabled ?? false), perform: perform)
    }

    /// Checks the password; on success runs the pending release once and closes the prompt.
    func submit(_ password: String) async {
        guard let request = pending, !busy, !password.isEmpty else { return }
        guard let passwords else { message = String(localized: "The password could not be checked."); return }
        await check(request) { try await passwords.verifyPassword(password) }
    }

    /// Touch ID for a routine prompt.
    func submitTouchID() async {
        guard let request = pending, !busy, request.offersTouchID, let passwords else { return }
        await check(request) { try await passwords.verifyWithTouchID(reason: request.action.lowercased()) }
    }

    private func check(_ request: Request, _ verify: () async throws -> Void) async {
        busy = true
        defer { busy = false }
        let generation = passwords?.sessionGeneration ?? 0
        do {
            try await verify()
        } catch is CancellationError {
            if request.level == .strict { pending = nil }
            message = nil
            return
        } catch MacVaultError.biometricUnavailable {
            message = String(localized: "Touch ID didn't work. Use your master password.")
            return
        } catch {
            message = MacLockModel.describe(error, now: now()) ?? String(localized: "The password could not be checked.")
            return
        }
        guard pending?.id == request.id else { return }   // cancelled (or locked) while checking
        pending = nil
        if request.level == .routine { grace = (generation, now().addingTimeInterval(Self.routineGraceSeconds)) }
        request.perform()
    }

    func cancel() { pending = nil; message = nil }

    /// Locking ends the grace and drops any prompt.
    func lockReset() { grace = nil; cancel() }
}

/// The master password prompt for `StrictItemGate`.
struct StrictItemSheet: View {
    let gate: StrictItemGate
    let request: StrictItemGate.Request
    @State private var password = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(request.level == .strict ? String(localized: "Enter your master password") : String(localized: "Confirm it's you")).font(.system(size: 15, weight: .semibold))
            Text(request.level == .strict
                 ? String(localized: "\(request.title) asks for the master password each time. \(request.action) after confirming.")
                 : String(localized: "Confirm it's you to continue. \(request.action) after confirming."))
                .font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Master password", text: $password).glassField().onSubmit(submit)
            if let message = gate.message { Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger) }
            HStack {
                if request.offersTouchID {
                    Button("Use Touch ID") { Task { await gate.submitTouchID() } }.disabled(gate.busy)
                }
                Spacer()
                Button("Cancel") { gate.cancel() }.keyboardShortcut(.cancelAction)
                Button("Confirm", action: submit).keyboardShortcut(.defaultAction).disabled(password.isEmpty || gate.busy)
            }
        }
        .padding(20).frame(width: 380)
        .task { if request.offersTouchID { await gate.submitTouchID() } }
        .foregroundStyle(theme.text)
    }

    private func submit() {
        let pw = password
        password = ""
        Task { await gate.submit(pw) }
    }
}
