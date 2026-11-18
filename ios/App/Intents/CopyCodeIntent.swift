import AppIntents
import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Sub-plan 06: the Shortcuts action "Copy code". It copies one pinned 2FA code with the app's clipboard rules
/// (local only, cleared after the Settings expiry) and returns the digits, so a shortcut can also type or fill
/// them. Shortcuts automations can run it, so:
/// - it runs only on an unlocked device (`requiresAuthentication`), and the codes' Keychain item opens only then;
/// - it reads only `PinnedCodeStore` (the first `maxShown` pins), never any other vault item;
/// - after Forget on lock (`expiresAt`) or when the secrets cannot be read, it fails with a message, never an old
///   code;
/// - the digits are never logged, shown in the dialog (only "Code copied") or put in the donation (only the chosen code's id and title).
/// Showing an already pinned code is not Pro-gated; pinning is.
struct CopyCodeIntent: AppIntent {
    static var title: LocalizedStringResource { "Copy code" }
    static var description: IntentDescription {
        IntentDescription("Copies a 2FA code you pinned in LocalGateKeys. The clipboard clears itself after the time chosen in Settings.")
    }
    static var authenticationPolicy: IntentAuthenticationPolicy { .requiresAuthentication }
    static var openAppWhenRun: Bool { false }
    #if os(macOS)
    /// The Mac app pins no codes and holds no codes Keychain group: the action is not offered there.
    static var isDiscoverable: Bool { false }
    #endif

    @Parameter(title: "Code")
    var item: CodeEntity

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let code = try Self.currentCode(for: item.id, store: CodeIntentEnvironment.makeStore(),
                                        at: CodeIntentEnvironment.now())
        CodeIntentEnvironment.clipboard().copy(code)
        // Siri says "Code copied" rather than reading the digits; shortcuts still get the value.
        return .result(value: code, dialog: IntentDialog(Self.copiedDialog))
    }

    /// What Siri says and shows after a copy: never the digits.
    static let copiedDialog: LocalizedStringResource = "Code copied"

    /// The digits of pinned code `id` at `date`, as the widgets show them. Fails when it is not pinned or not among
    /// the `maxShown` codes shown, or when no current code can be read (device locked, Forget on lock, expired).
    static func currentCode(for id: String, store: PinnedCodeStore, at date: Date) throws -> String {
        guard store.pinnedIDs.contains(id) else { throw CopyCodeError.notPinned }
        let shown = store.codes(at: date)
        if let code = shown.first(where: { $0.0.id == id }) { return code.code }
        throw shown.count >= PinnedCodeStore.maxShown ? CopyCodeError.notPinned : CopyCodeError.unavailable
    }
}

/// Why "Copy code" gave no code, in the person's language.
enum CopyCodeError: Error, CustomLocalizedStringResourceConvertible {
    case notPinned
    case unavailable

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .notPinned:
            return "Pin this 2FA code in LocalGateKeys first. Shortcuts can use your first \(PinnedCodeStore.maxShown) pinned codes."
        case .unavailable:
            return "Open LocalGateKeys to show codes"
        }
    }
}

/// Where the intent and its query read and copy. The app uses the shared store read-only (never migrating or
/// deleting, like the widgets) and the app's clipboard; tests replace these.
@MainActor
enum CodeIntentEnvironment {
    static var makeStore: @MainActor () -> PinnedCodeStore = { CodeIntentEnvironment.readOnlyStore() }
    static var clipboard: @MainActor () -> any SecretCopying = { CodeIntentEnvironment.appClipboard() }
    static var now: @MainActor () -> Date = { Date() }

    /// The pin list in the app group's defaults and the codes' own Keychain group; nothing without that group.
    nonisolated static func readOnlyStore() -> PinnedCodeStore {
        let keychain: any KeychainAccess
        if let group = AppGroup.codesKeychainAccessGroup { keychain = SystemKeychainAccess(accessGroup: group) }
        else { keychain = NoKeychainAccess() }
        return PinnedCodeStore(defaults: UserDefaults(suiteName: AppGroup.identifier) ?? .standard, keychain: keychain)
    }

    static func appClipboard() -> any SecretCopying {
        #if os(macOS)
        return MacClipboard.shared
        #else
        return SecretClipboard.shared
        #endif
    }
}
