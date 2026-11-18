import AppKit
import AppSharedMac

/// Windows settings the Mac lacked (parity report 2026-11-14): what counts as activity for auto-lock, asking before a
/// 2FA code is copied, opening documents in other apps, and how many automatic backups to keep. Stored in the app
/// group's defaults (`AppSettings.defaults`), per device, never synced. Defaults are Windows' (`settings.py`).
enum MacExtraSettings {
    static let idleSourceKey = "settings.mac.idleSource"
    static let totpConfirmKey = "settings.mac.totpConfirm"
    static let documentOpenKey = "settings.mac.documentOpenEnabled"
    static let documentOpenWarningSeenKey = "settings.mac.documentOpenWarningSeen"
    static let automaticBackupCountKey = "settings.mac.automaticBackupCount"

    // MARK: idle source (Windows `idle_source`, "computer" by default)

    /// What resets the auto-lock timer.
    enum IdleSource: String, CaseIterable, Identifiable {
        /// Keyboard or mouse anywhere on the Mac (`CGEventSource`), Windows' system idle time.
        case computer
        /// Only input in LocalGateKeys' own windows.
        case vault

        var id: String { rawValue }

        var label: String {
            switch self {
            case .computer: String(localized: "Computer activity")
            case .vault: String(localized: "Vault activity")
            }
        }

        /// Seconds idle: `system` is the Mac's idle time, `app` the time since the last input in the app's windows.
        /// Input in the app is input on the Mac too, so Computer takes the shorter of the two (the Mac's behaviour
        /// before this setting); Vault ignores the rest of the Mac.
        func idleSeconds(system: TimeInterval, app: TimeInterval) -> TimeInterval {
            switch self {
            case .computer: min(app, system)
            case .vault: app
            }
        }
    }

    static func idleSource(_ defaults: UserDefaults) -> IdleSource {
        defaults.string(forKey: idleSourceKey).flatMap(IdleSource.init(rawValue:)) ?? .computer
    }

    // MARK: 2FA confirm (Windows `totp_confirm`, off by default)

    /// True only when the switch is exactly on (Windows `requires_totp_confirmation`).
    static func totpConfirm(_ defaults: UserDefaults) -> Bool {
        (defaults.object(forKey: totpConfirmKey) as? Bool) == true
    }

    // MARK: documents (Windows `document_open_enabled`, on by default; `document_open_warning_seen`)

    static func documentOpenEnabled(_ defaults: UserDefaults) -> Bool {
        (defaults.object(forKey: documentOpenKey) as? Bool) ?? true
    }

    static func documentOpenWarningSeen(_ defaults: UserDefaults) -> Bool {
        (defaults.object(forKey: documentOpenWarningSeenKey) as? Bool) ?? false
    }

    // MARK: automatic backups (Windows `automatic_backup_count`, 5 by default, 0–20)

    static let automaticBackupChoices = [0, 3, 5, 10, 20]
    static let defaultAutomaticBackupCount = 5

    /// Windows `_validated_backup_count`: an integer from 0 to 20, else 5.
    static func validatedBackupCount(_ value: Any?) -> Int {
        // A stored number comes back as NSNumber, which `is Bool` matches for 0 and 1: tell booleans apart by CF type.
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !(value is String) else { return defaultAutomaticBackupCount }
        let n = number.intValue
        return (0...20).contains(n) ? n : defaultAutomaticBackupCount
    }

    static func automaticBackupCount(_ defaults: UserDefaults) -> Int {
        validatedBackupCount(defaults.object(forKey: automaticBackupCountKey))
    }

    /// The offered choices, plus a stored value that isn't one of them.
    static func backupCountOptions(current: Int) -> [Int] { Array(Set(automaticBackupChoices + [current])).sorted() }

    static func backupCountLabel(_ n: Int) -> String {
        n == 0 ? String(localized: "Off") : String(localized: "\(n) backups")
    }

    // MARK: Help (Windows `settings_sections.py` `build_help`)

    static let privacyPolicyURL = URL(string: "https://localgatekeys.app/legal/app/privacy.html")!
    static let licenceAgreementURL = URL(string: "https://localgatekeys.app/legal/app/eula.html")!
}

/// Settings › Locking › Ask before releasing 2FA codes: the question asked before each in-app copy of a 2FA code
/// (the code list, ⌘T, the detail panel, the menu bar). Windows asks when the browser extension wants a code; on the
/// Mac, system AutoFill already needs a pick and an unlock each time, so the switch covers the app's own copies.
@MainActor
enum MacTOTPConfirm {
    /// True when the copy may go ahead: the switch is off, or the person answered Copy.
    static func allow(title: String, defaults: UserDefaults = AppSettings.shared.defaults,
                      ask: @MainActor (String) -> Bool = askWithAlert) -> Bool {
        guard MacExtraSettings.totpConfirm(defaults) else { return true }
        return ask(title)
    }

    static func askWithAlert(_ title: String) -> Bool {
        QuickAccessBridge.activate()
        let alert = NSAlert()
        alert.messageText = String(localized: "Copy the 2FA code?")
        alert.informativeText = title
        alert.addButton(withTitle: String(localized: "Copy"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }
}
