import Foundation
import Observation

/// The setup steps (UX plan 2026-10-27 workstream 4), the iPhone's and the Mac's versions of the shared list
/// (Windows `app/onboarding.py`, Android `settings/Onboarding.kt`). Creating the vault happens before the app
/// opens, so it is always done; every other step can be skipped.
public enum SetupStep: String, CaseIterable, Identifiable, Sendable {
    case vault, unlock, importItems = "import", phrase, autofill

    public var id: String { rawValue }

    /// 1-based position in the list.
    public var number: Int { (Self.allCases.firstIndex(of: self) ?? 0) + 1 }

    public static func of(_ raw: String) -> SetupStep? { SetupStep(rawValue: raw) }

    #if os(macOS)
    public var title: String {
        switch self {
        case .vault: String(localized: "Your vault is ready")
        case .unlock: String(localized: "Unlock with Touch ID")
        case .importItems: String(localized: "Import your passwords")
        case .phrase: String(localized: "Check your recovery phrase")
        case .autofill: String(localized: "Turn on the Safari extension and AutoFill")
        }
    }

    public var text: String {
        switch self {
        case .vault: String(localized: "Everything you save stays encrypted on this Mac.")
        case .unlock: String(localized: "Open the vault with your fingerprint instead of typing the master password each time.")
        case .importItems: String(localized: "Bring logins over from another password manager, Apple Passwords, a CSV file or a phone backup.")
        case .phrase: String(localized: "Create a recovery phrase and retype three of its words, so a forgotten master password is not the end.")
        case .autofill: String(localized: "Fill and save logins in Safari and in apps. Turn them on in Devices & connections.")
        }
    }

    public var action: String {
        switch self {
        case .vault: String(localized: "Continue")
        case .unlock: String(localized: "Set up Touch ID")
        case .importItems: String(localized: "Import…")
        case .phrase: String(localized: "Open recovery phrase")
        case .autofill: String(localized: "Open Devices & connections")
        }
    }

    public var icon: String {
        switch self {
        case .vault: "lock.shield"
        case .unlock: "touchid"
        case .importItems: "square.and.arrow.down"
        case .phrase: "key"
        case .autofill: "safari"
        }
    }
    #else
    public var title: String {
        switch self {
        case .vault: String(localized: "Your vault is ready")
        case .unlock: String(localized: "Unlock with Face ID")
        case .importItems: String(localized: "Import your passwords")
        case .phrase: String(localized: "Add an app password")
        case .autofill: String(localized: "Turn on AutoFill")
        }
    }

    public var text: String {
        switch self {
        case .vault: String(localized: "Everything you save stays encrypted on this iPhone.")
        case .unlock: String(localized: "LocalGateKeys opens with Face ID, Touch ID or your passcode, the same as your iPhone.")
        case .importItems: String(localized: "Bring in Apple Passwords, a CSV or an export file from another password manager.")
        case .phrase: String(localized: "An optional app password with a recovery phrase. You confirm three words from the phrase when you set it up.")
        case .autofill: String(localized: "Fill your logins in apps and in Safari. Choose LocalGateKeys as the AutoFill provider.")
        }
    }

    public var action: String {
        switch self {
        case .vault: String(localized: "Continue")
        case .unlock: String(localized: "Got it")
        case .importItems: String(localized: "Import…")
        case .phrase: String(localized: "Open Settings")
        case .autofill: String(localized: "Open AutoFill settings")
        }
    }

    public var icon: String {
        switch self {
        case .vault: "lock.shield"
        case .unlock: "faceid"
        case .importItems: "square.and.arrow.down"
        case .phrase: "key"
        case .autofill: "key.viewfinder"
        }
    }
    #endif
}

/// Setup progress on this device (`AppSettings`, never synced: each device has its own setup). The pages run once
/// (Skip on every page, Skip setup on the first); the steps left stay on the vault's "Finish setting up · n of 5"
/// card until done or hidden; Settings › Show setup again opens the pages and the card again.
@MainActor
@Observable
public final class Onboarding {
    public private(set) var done: Set<SetupStep>
    /// The setup pages are showing.
    public private(set) var pagesOpen: Bool
    public private(set) var cardHidden: Bool
    @ObservationIgnored private let settings: AppSettings

    public static let skip = String(localized: "Skip")
    public static let skipSetup = String(localized: "Skip setup")
    public static let hide = String(localized: "Hide")
    public static let showAgainTitle = String(localized: "Show setup again")
    public static let title = String(localized: "Set up LocalGateKeys")

    public init(settings: AppSettings = .shared) {
        self.settings = settings
        done = Set(settings.setupDone.compactMap(SetupStep.of)).union([.vault])
        pagesOpen = !settings.setupSeen
        cardHidden = settings.setupCardHidden
    }

    public var remaining: [SetupStep] { SetupStep.allCases.filter { !done.contains($0) } }

    /// "Finish setting up · 3 of 5" while steps remain, the pages are closed and the card is not hidden; else nil.
    public var cardText: String? {
        if pagesOpen || cardHidden || remaining.isEmpty { return nil }
        return Self.cardText(done: done.count, total: SetupStep.allCases.count)
    }

    public func complete(_ step: SetupStep) {
        guard !done.contains(step) else { return }
        done.insert(step)
        settings.setupDone = SetupStep.allCases.filter { done.contains($0) && $0 != .vault }.map(\.rawValue)
    }

    /// Steps finished elsewhere in the app (Face ID or Touch ID on, a phrase enrolled, AutoFill on) count as done.
    public func detected(_ steps: some Sequence<SetupStep>) {
        for step in steps { complete(step) }
    }

    /// The pages were finished or skipped: they do not open again by themselves.
    public func closePages() {
        pagesOpen = false
        settings.setupSeen = true
    }

    public func hideCard() {
        cardHidden = true
        settings.setupCardHidden = true
    }

    /// Settings › Show setup again (and a tap on the card): the pages open at the first open step and the card
    /// can show again.
    public func showAgain() {
        cardHidden = false
        settings.setupCardHidden = false
        pagesOpen = true
    }

    /// The page to show first: the first step not done (the vault page when everything is done).
    public func firstPage() -> SetupStep { remaining.first ?? .vault }

    /// The step after `step` that is not done; nil at the end.
    public func next(after step: SetupStep) -> SetupStep? {
        SetupStep.allCases.drop(while: { $0 != step }).dropFirst().first { !done.contains($0) }
    }

    public static func cardText(done: Int, total: Int) -> String { String(localized: "Finish setting up · \(done) of \(total)") }

    public static func pageCount(_ step: SetupStep) -> String { String(localized: "Step \(step.number) of \(SetupStep.allCases.count)") }
}
