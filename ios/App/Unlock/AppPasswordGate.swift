import Foundation
import LocalAuthentication
import UIKit
import AppShared

/// The iPhone owner check before an action that gives the vault's secrets away (audit 2026-11-10): a plaintext export,
/// earlier passwords, emergency access, the sync rollback acknowledgement, sharing a collection, attached documents.
/// With the app password on the device passcode never passes it (the Mac asks for the master password at the same
/// points): the Face ID shortcut (`.biometryCurrentSet`, and the key it releases must be the open vault's), else the
/// app password, checked as Settings checks it (`AppPasswordController.verify`: the unlock's wrong-try delay and
/// count, today's key file and YubiKey). Nil while the app password is off: the caller keeps its own check.
@MainActor
enum AppPasswordGate {
    /// The app's lock, set at launch: the open vault's key, its factors and whether it is the duress session.
    static weak var lock: AppLockModel?

    private enum FaceIDAnswer { case confirmed, cancelled, usePassword }

    /// True once confirmed, false when declined or not possible; nil when the app password is off.
    static func confirm(_ reason: String) async -> Bool? {
        guard let store = AppPasswordStore.shared(), store.isOn else { return nil }
        guard let lock = Self.lock, lock.state == .unlocked, let keychain = lock.keychain else { return false }
        if lock.biometricShortcut, !lock.secondSession {
            switch await faceID(reason, store: store, keychain: keychain) {
            case .confirmed: return lock.state == .unlocked
            case .cancelled: return false
            case .usePassword: break
            }
        }
        var problem: String?
        while true {
            guard let password = await askPassword(reason, problem: problem) else { return false }
            guard !password.isEmpty else { problem = AppLockModel.wrongPasswordMessage; continue }
            guard lock.state == .unlocked, let current = lock.keychain else { return false }
            let controller = AppPasswordController(store: store, keychain: current, factors: lock.factors,
                                                   secondSession: lock.secondSession)
            do {
                try await controller.verify(current: password)
                return lock.state == .unlocked
            } catch {
                problem = AppLockModel.message(for: error) ?? AppLockModel.wrongPasswordMessage
            }
        }
    }

    /// The Face ID shortcut, as at unlock (no reuse of an earlier match); "Use App Password" or a failure goes on to
    /// the password.
    private static func faceID(_ reason: String, store: AppPasswordStore, keychain: any KeychainVault) async -> FaceIDAnswer {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        ctx.localizedFallbackTitle = String(localized: "Use App Password")
        do {
            try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let e as LAError where e.code == .userCancel || e.code == .systemCancel || e.code == .appCancel {
            return .cancelled
        } catch {
            return .usePassword
        }
        guard var key = try? store.biometric.load(context: ctx) else { return .usePassword }
        defer { for i in key.indices { key[i] = 0 } }
        guard var open = try? keychain.read(.localKey) else { return .usePassword }
        defer { for i in open.indices { open[i] = 0 } }
        return !open.isEmpty && Envelope.same(open, key) ? .confirmed : .usePassword
    }

    /// The app password, typed into an alert over whatever is on screen; nil when cancelled or nothing can show it.
    private static func askPassword(_ reason: String, problem: String?) async -> String? {
        guard let presenter = await presenter() else { return nil }
        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let alert = PasswordAlert(title: String(localized: "Confirm it's you"),
                                      message: problem.map { "\(reason)\n\n\($0)" } ?? reason, preferredStyle: .alert)
            alert.onFinish = { continuation.resume(returning: $0) }
            alert.addTextField { field in
                field.isSecureTextEntry = true
                field.textContentType = .password
                field.placeholder = String(localized: "App password")
            }
            alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel) { [weak alert] _ in
                alert?.finish(nil)
            })
            alert.addAction(UIAlertAction(title: String(localized: "Confirm"), style: .default) { [weak alert] _ in
                alert?.finish(alert?.textFields?.first?.text ?? "")
            })
            presenter.present(alert, animated: true)
        }
    }

    /// `confirm`, else Face ID, Touch ID or the device passcode. When the check cannot run at all (no passcode set,
    /// Face ID locked after too many tries, another failure) an alert says why instead of nothing happening (review
    /// L3); a cancel says nothing.
    static func confirmOwner(_ reason: String) async -> Bool {
        if let answer = await confirm(reason) { return answer }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            await showProblem(ownerCheckMessage(error) ?? ownerCheckFailedText)
            return false
        }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            if let message = ownerCheckMessage(error) { await showProblem(message) }
            return false
        }
    }

    nonisolated static let ownerCheckFailedText = String(localized: "Could not confirm it's you. Try again.")

    /// Why the owner check could not confirm; nil for a cancel (the person chose not to).
    static func ownerCheckMessage(_ error: (any Error)?) -> String? {
        guard let e = error as? LAError else { return ownerCheckFailedText }
        switch e.code {
        case .userCancel, .systemCancel, .appCancel, .userFallback: return nil
        case .passcodeNotSet: return String(localized: "Set a device passcode in Settings to use LocalGateKeys.")
        case .biometryLockout: return AppLockModel.biometryLockoutMessage
        default: return ownerCheckFailedText
        }
    }

    /// A one-button alert over whatever is on screen (sheets included).
    static func showProblem(_ message: String) async {
        guard let presenter = await presenter() else { return }
        let alert = UIAlertController(title: String(localized: "Confirm it's you"), message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        presenter.present(alert, animated: true)
    }

    /// The key window's top presented view controller. An alert still on screen or going away (the one whose button
    /// started this check) is waited out, for up to a second.
    private static func presenter() async -> UIViewController? {
        for _ in 0..<20 {
            guard let scene = PrivacyCoverController.currentScene(),
                  let window = scene.windows.first(where: { $0.isKeyWindow })
                    ?? scene.windows.first(where: { $0.windowLevel == .normal }),
                  var top = window.rootViewController else { return nil }
            while let next = top.presentedViewController, !next.isBeingDismissed { top = next }
            if !(top is UIAlertController), top.presentedViewController == nil { return top }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return nil
    }
}

/// The password alert: its continuation is resumed exactly once, by a button or, when the alert goes away without one
/// (the app locks, the scene disconnects), with nil.
@MainActor
private final class PasswordAlert: UIAlertController {
    var onFinish: ((String?) -> Void)?

    func finish(_ value: String?) {
        guard let done = onFinish else { return }
        onFinish = nil
        done(value)
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // A button's handler runs after the dismissal ends, so after this: give it a second to resume first, then
        // resume nil if none did. The task keeps the alert alive until then.
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1))
            self.finish(nil)
        }
    }
}
