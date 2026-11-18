import SwiftUI
import Observation
import AppSharedMac

/// The one gate for logins with `policy.require_master_password` (Windows `secrets.py` with
/// `allow_hello=not strict`): every release of such a login's secrets — copying the username, password or
/// one-time code, showing the password, code or notes, opening the editor — asks for the master password
/// first. Never Touch ID, no grace period: each release asks again. The vault's unlock throttle applies, and a
/// cancelled or failed prompt releases nothing. Other items pass straight through.
///
/// It also approves SSH agent signatures (`approveSSH`): Touch ID when turned on, else the master password, then the
/// same program may use the same key for 10 minutes without asking (Windows `local_clients` remembers 10 minutes).
@MainActor @Observable
final class StrictItemGate {
    /// Strict: master password every time. Routine (Windows `reauthenticate(allow_hello=True)`): Touch ID when
    /// turned on, else the master password, then a 120 s grace for this unlock session. Approval: an SSH agent
    /// signature confirmed with the master password (no routine grace).
    enum Level: Equatable { case strict, routine, approval }

    struct Request: Identifiable {
        let id = UUID()
        let title: String
        /// "Copy username", "Show notes", …
        let action: String
        let level: Level
        let offersTouchID: Bool
        let perform: () -> Void
        /// Run when the prompt goes without `perform` (Cancel, a lock, a newer prompt): an SSH approval answers "no".
        var onCancel: (() -> Void)? = nil
        /// SSH approvals: shows "Allow for 10 minutes" (off by default).
        var offersRemember = false
    }

    /// Windows `ROUTINE_REAUTH_GRACE_SECONDS`.
    static let routineGraceSeconds: TimeInterval = 120
    /// Windows `local_clients` remembering: an approval with "Remember" ticked is not asked again for 10 minutes for
    /// the same (program, SSH key).
    static let sshRememberSeconds: TimeInterval = 600
    /// Windows `local_clients` queue: how long a second SSH request waits for the first one's prompt.
    static let sshQueueSeconds: Int64 = 60

    /// The prompt on screen, if any.
    private(set) var pending: Request?
    /// "Allow for 10 minutes" on the SSH approval sheet (off each time the sheet opens).
    var rememberApproval = false
    private(set) var message: String?
    private(set) var busy = false
    /// Whether the prompt on screen may use Touch ID (never for strict logins).
    var offersTouchID: Bool { pending?.offersTouchID ?? false }

    @ObservationIgnored private let passwords: (any MasterPasswordService)?
    @ObservationIgnored private let now: () -> Date
    /// (session generation, expiry) of the routine grace.
    @ObservationIgnored private var grace: (generation: Int, until: Date)?
    /// "program path, NUL, item id" -> (session generation, expiry) of each remembered SSH approval.
    @ObservationIgnored private var sshApprovals: [String: (generation: Int, until: Date)] = [:]
    /// True while an SSH approval runs (the next one waits).
    @ObservationIgnored private var sshApprovalActive = false
    /// Copy once (feature pack §4.1): the session generation and the items copied in it.
    @ObservationIgnored private var copiedOnce: (generation: Int, ids: Set<String>) = (-1, [])

    init(passwords: (any MasterPasswordService)?, now: @escaping () -> Date = Date.init) {
        self.passwords = passwords; self.now = now
    }

    /// Master password on every release: `policy.require_master_password`, or (feature pack §4) a login whose access
    /// rule expired or comes from a newer version (`MacAccess`).
    static func isStrict(_ item: VaultItem) -> Bool {
        MacAccess.requiresMasterPassword(item.record)
    }

    /// Feature pack §4.1 copy once: the first copy in an unlock session is cleared after at most 10 s.
    static let copyOnceClearSeconds: TimeInterval = 10

    /// A copy of one of `item`'s secrets. `perform` gets the clipboard limit for this copy (nil: the user's setting).
    /// Copy once (§4.1): the first copy of the item's secrets in this unlock session passes as usual with a 10 s limit;
    /// every further copy of them in the session asks for the master password. `routine` copies (the password) go
    /// through `releaseRoutine`, others through `release`.
    func releaseCopy(_ item: VaultItem, action: String, routine: Bool = false,
                     perform: @escaping (_ limit: TimeInterval?) -> Void) {
        guard MacAccess.rules(item.record).copyOnce else {
            if routine { releaseRoutine(item, action: action) { perform(nil) } } else { release(item, action: action) { perform(nil) } }
            return
        }
        let generation = passwords?.sessionGeneration ?? 0
        if copiedOnce.generation != generation { copiedOnce = (generation, []) }
        let id = item.id
        let first: () -> Void = { [weak self] in
            if let self, self.copiedOnce.generation == generation { self.copiedOnce.ids.insert(id) }
            perform(Self.copyOnceClearSeconds)
        }
        if copiedOnce.ids.contains(id) {
            ask(item, action: action, level: .strict) { perform(Self.copyOnceClearSeconds) }
        } else if routine {
            releaseRoutine(item, action: action, perform: first)
        } else {
            release(item, action: action, perform: first)
        }
    }

    /// Whether `item` was copied in this unlock session under copy once (the next copy asks for the master password).
    func copiedOnceThisSession(_ item: VaultItem) -> Bool {
        copiedOnce.generation == (passwords?.sessionGeneration ?? 0) && copiedOnce.ids.contains(item.id)
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
        if pending?.level == .approval { cancel() }
        guard pending == nil else { return false }
        message = nil
        pending = Request(title: title, action: action, level: .strict, offersTouchID: false, perform: perform)
        return true
    }

    /// `confirmMasterPassword` that waits for the answer (sharing a collection, sub-plan 07: desktop
    /// `_confirm_handover`): true once the master password is confirmed; false when the prompt is cancelled, dropped by
    /// a lock or a newer prompt, or another prompt is open (that one is never replaced).
    func confirmMasterPassword(title: String, action: String) async -> Bool {
        if pending?.level == .approval { cancel() }
        guard pending == nil else { return false }
        let answer = ApprovalAnswer()
        return await withCheckedContinuation { continuation in
            guard answer.attach(continuation) else { return }
            message = nil
            pending = Request(title: title, action: action, level: .strict, offersTouchID: false,
                              perform: { answer.resolve(true) }, onCancel: { answer.resolve(false) })
        }
    }

    private var graceValid: Bool {
        guard let grace, let passwords else { return false }
        return grace.generation == passwords.sessionGeneration && now() < grace.until
    }

    // MARK: SSH agent approvals

    /// Asks whether `programName` may sign with the SSH key item `itemID` (its `title`), on `host` when the
    /// connection named one. Requests are handled one at a time (Windows `local_clients` queue): a second one waits up
    /// to 60 s for the first, then is refused. An approval remembered for the same program path and key answers at
    /// once (an unknown program is never remembered). Otherwise Touch ID when it is turned on (never remembered);
    /// else (or when Touch ID cannot be used) the master password sheet, after `bringForward` shows the window, with
    /// "Allow for 10 minutes" off by default. False when refused, cancelled, locked or another prompt is open; a
    /// cancelled task (the agent's deadline) withdraws its prompt.
    func approveSSH(program: String?, programName: String, itemID: String, title: String, host: String?,
                    bringForward: @MainActor () -> Void = {}) async -> Bool {
        guard await enterSSHQueue() else { return false }
        defer { sshApprovalActive = false }
        guard let passwords, passwords.isUnlocked, !Task.isCancelled else { return false }
        let rememberKey = program.map { "\($0)\u{0}\(itemID)" }
        if let rememberKey, let approval = sshApprovals[rememberKey], approval.generation == passwords.sessionGeneration,
           now() < approval.until {
            return true
        }
        let generation = passwords.sessionGeneration
        let action = host.map { String(localized: "ssh_agent.approve.host", defaultValue: "Allow \(programName) to sign in to \($0) with this SSH key") }
            ?? String(localized: "ssh_agent.approve", defaultValue: "Allow \(programName) to use this SSH key")
        if passwords.routineTouchIDEnabled {
            do {
                try await passwords.verifyWithTouchID(reason: action.prefix(1).lowercased() + action.dropFirst())
                // Never remembered: the Touch ID prompt has no "Remember" choice.
                return !Task.isCancelled && passwords.isUnlocked && passwords.sessionGeneration == generation
            } catch is CancellationError {
                return false
            } catch {
                // Touch ID can't be used now: the master password instead.
            }
        }
        guard pending == nil, !Task.isCancelled else { return false }
        bringForward()
        let answer = await askApproval(title: title.isEmpty ? VaultItem.kindLabel("ssh_key") : title, action: action,
                                       canRemember: rememberKey != nil)
        guard answer.approved, !Task.isCancelled, passwords.isUnlocked, passwords.sessionGeneration == generation else { return false }
        if answer.remember, let rememberKey {
            sshApprovals[rememberKey] = (generation, now().addingTimeInterval(Self.sshRememberSeconds))
        }
        return true
    }

    /// Windows `local_clients`: one approval at a time; a waiting request gives up after 60 s or when cancelled.
    private func enterSSHQueue() async -> Bool {
        let clock = ContinuousClock()
        let start = clock.now
        while sshApprovalActive {
            guard !Task.isCancelled, clock.now - start < .seconds(Self.sshQueueSeconds) else { return false }
            try? await Task.sleep(for: .milliseconds(50))
        }
        sshApprovalActive = true
        return true
    }

    /// The master password sheet for one approval; approved once confirmed (and whether "Remember" was ticked),
    /// refused when it goes any other way.
    private func askApproval(title: String, action: String, canRemember: Bool) async -> (approved: Bool, remember: Bool) {
        let answer = ApprovalAnswer()
        rememberApproval = false
        let request = Request(title: title, action: action, level: .approval, offersTouchID: false,
                              perform: { [weak self] in answer.remember = self?.rememberApproval ?? false; answer.resolve(true) },
                              onCancel: { answer.resolve(false) }, offersRemember: canRemember)
        let requestID = request.id
        let approved = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard answer.attach(continuation) else { return }   // cancelled before the sheet was shown
                message = nil
                pending = request
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                if self?.pending?.id == requestID { self?.cancel() } else { answer.resolve(false) }
            }
        }
        return (approved, approved && canRemember && answer.remember)
    }

    private func ask(_ item: VaultItem, action: String, level: Level, perform: @escaping () -> Void) {
        // An SSH approval on screen is withdrawn (its client gets FAILURE at once), never silently replaced; a prompt
        // someone is waiting on (`confirmMasterPassword(title:action:) async`) is answered "no".
        if pending?.level == .approval { cancel() } else { pending?.onCancel?() }
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
            if request.level != .routine { pending = nil; request.onCancel?() }
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

    func cancel() {
        let dropped = pending
        pending = nil; message = nil
        dropped?.onCancel?()
    }

    /// Locking ends the grace and the remembered SSH approvals, and drops any prompt.
    func lockReset() { grace = nil; sshApprovals = [:]; copiedOnce = (-1, []); cancel() }
}

/// The one answer of an SSH approval sheet: the first of confirm, cancel or deadline wins.
@MainActor
private final class ApprovalAnswer {
    private var continuation: CheckedContinuation<Bool, Never>?
    private var answered: Bool?
    /// Whether "Allow for 10 minutes" was ticked when it was confirmed.
    var remember = false

    /// Waits on `continuation`; false (and resumed at once) when the answer is already in.
    func attach(_ continuation: CheckedContinuation<Bool, Never>) -> Bool {
        if let answered { continuation.resume(returning: answered); return false }
        self.continuation = continuation
        return true
    }

    func resolve(_ value: Bool) {
        guard answered == nil else { return }
        answered = value
        if let continuation { self.continuation = nil; continuation.resume(returning: value) }
    }
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
            if request.level == .approval {
                Text(request.title).font(.system(size: 13, weight: .medium)).foregroundStyle(theme.text)
            }
            Text(request.level == .strict
                 ? String(localized: "\(request.title) asks for the master password each time. \(request.action) after confirming.")
                 : String(localized: "Confirm it's you to continue. \(request.action) after confirming."))
                .font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Master password", text: $password).glassField().onSubmit(submit)
            if request.offersRemember {
                Toggle(String(localized: "local_clients.remember", defaultValue: "Allow for 10 minutes"),
                       isOn: Binding(get: { gate.rememberApproval }, set: { gate.rememberApproval = $0 }))
                    .toggleStyle(.checkbox).font(.system(size: 12.5))
            }
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
