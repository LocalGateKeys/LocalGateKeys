import Foundation
import Observation
import WidgetKit
import AppShared

/// The app's one pin list, over the live WatchConnectivity link.
@MainActor
enum WatchCodes {
    static let shared = WatchCodesModel(link: SystemWatchLink.shared)
}

/// Sends one `WatchMessage` to the paired watch's LocalGateKeys app (the live one is `SystemWatchLink`).
@MainActor
protocol WatchSending: AnyObject {
    /// A watch is paired and has the LocalGateKeys watch app installed.
    var isAvailable: Bool { get }
    func send(_ message: WatchMessage)
}

/// UX plan workstream 12, iPhone side: which 2FA codes are pinned to the Apple Watch, and when the watch
/// gets them or forgets them. Pins (item ids, no secret) and the first pinned codes' secrets live in
/// `PinnedCodeStore` (app-group defaults and the app's shared Keychain group) so the widgets can show them too.
/// The secrets leave the phone only in a `WatchMessage` over WatchConnectivity (encrypted between the paired
/// devices by Apple; never through a server), and only on the Pro plan, like all 2FA. Pinning is Pro; a code
/// already pinned is still shown by the widgets on any plan.
@MainActor @Observable
final class WatchCodesModel {
    static let forgetOnLockKey = "watch.forgetOnLock"

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored let pinStore: PinnedCodeStore
    @ObservationIgnored let link: any WatchSending
    /// Asks WidgetKit to rebuild the codes widgets' timelines; called after every change to `pinStore`.
    @ObservationIgnored private let reloadWidgets: @MainActor () -> Void
    private(set) var pins: [String]
    /// "Forget on watch" when the vault locks (default off: the watch keeps working with the phone away). Also
    /// deletes the widgets' copy of the secrets, and hides them from the moment the vault would auto-lock.
    var forgetOnLock: Bool {
        didSet {
            defaults.set(forgetOnLock, forKey: Self.forgetOnLockKey)
            if !forgetOnLock, !frozen { pinStore.expiresAt = nil; reloadWidgets() }
        }
    }
    /// Only an unlocked vault writes secrets: a commit finishing after the lock writes nothing.
    @ObservationIgnored private var isUnlocked = false
    /// Sub-plan 08: the open vault is the duress password's second vault. The real vault's pins and the widgets' data
    /// stay as they are (never pruned or wiped); a pin tap there changes nothing. The watch shows the second vault's
    /// own pins, which are none (scan 2026-11-12 APL-I1).
    var frozen = false

    /// The second vault opened (review M1): freezes the pins and hides the widgets' codes now (the data stays; the
    /// next real unlock shows them again), so the real vault's codes never show beside the second vault. The watch
    /// gets the second vault's pinned codes (none) whatever "Forget on watch" says, so it matches the phone.
    func freezeForSecondVault() {
        frozen = true
        isUnlocked = false
        pinStore.expiresAt = Date()
        reloadWidgets()
        link.send(.forget)   // nothing is stored about this: every real unlock sends the real pins again
    }
    /// The newest snapshot written this unlock (an older one arriving late is ignored).
    @ObservationIgnored private var lastRevision: Int64 = -1

    /// `defaults` holds the "forget on lock" setting and, before this version, the pin list (moved once into
    /// `pinStore`). `pinStore` defaults to the shared store the widgets read.
    init(link: any WatchSending, defaults: UserDefaults = .standard, pinStore: PinnedCodeStore? = nil,
         reloadWidgets: @escaping @MainActor () -> Void = { WidgetCenter.shared.reloadAllTimelines() }) {
        let store = pinStore ?? WatchCodesModel.sharedStore()
        store.migrateLegacy(from: defaults)
        self.link = link; self.defaults = defaults; self.pinStore = store; self.reloadWidgets = reloadWidgets
        pins = store.pinnedIDs
        forgetOnLock = defaults.bool(forKey: Self.forgetOnLockKey)
    }

    /// The store in the app group's defaults and the codes' own Keychain group (`LGK_CODES_KEYCHAIN_GROUP`, which
    /// holds nothing else). No usable group (unsigned build): nothing is stored. A copy an earlier build of this
    /// branch wrote to the app-only or the shared group is deleted.
    static func sharedStore() -> PinnedCodeStore {
        for old in [AppGroup.appKeychainAccessGroup, AppGroup.keychainAccessGroup] {
            if let group = AppGroup.usableGroup(old), group != AppGroup.codesKeychainAccessGroup {
                SystemKeychainAccess(accessGroup: group).delete(key: PinnedCodeStore.secretsKey)
            }
        }
        let keychain: any KeychainAccess
        if let group = AppGroup.codesKeychainAccessGroup { keychain = SystemKeychainAccess(accessGroup: group) }
        else { keychain = NoKeychainAccess() }
        return PinnedCodeStore(defaults: UserDefaults(suiteName: AppGroup.identifier) ?? .standard, keychain: keychain)
    }

    var watchAvailable: Bool { link.isAvailable }
    func isPinned(_ itemID: String) -> Bool { !frozen && pins.contains(itemID) }
    var canPinMore: Bool { pins.count < WatchMessage.maxPins }

    enum ToggleResult: Equatable { case pinned, unpinned, limitReached, needsPro }

    /// "Show on Apple Watch" / unpin for one item, then the whole pinned set is sent again (so an unpinned
    /// secret is removed from the watch and from the widgets' store).
    @discardableResult
    func toggle(_ itemID: String, snapshot: StoreSnapshot, isPro: Bool) -> ToggleResult {
        let pinning = !pins.contains(itemID)
        if frozen { return isPro ? .limitReached : .needsPro }
        if pinning && !isPro { return .needsPro }
        guard let next = WatchPins.toggle(itemID, in: pins) else { return .limitReached }
        pins = next
        pinStore.pinnedIDs = pins
        send(snapshot: snapshot, isPro: isPro)
        return pinning ? .pinned : .unpinned
    }

    /// Stores the pinned codes for the widgets and sends them to the watch (none without Pro). Called after a
    /// pin change.
    func send(snapshot: StoreSnapshot, isPro: Bool) {
        let hide = hidden(snapshot)
        let all = WatchPins.codes(pins: pins, snapshot: snapshot).filter { !hide.contains($0.id) }
        pinStore.replace(all)
        reloadWidgets()
        let codes = isPro ? all : []
        link.send(codes.isEmpty ? .forget : .replace(codes))
    }

    /// The vault unlocked: the widgets' secrets are written again from the vault (they are gone after "Forget
    /// on lock", missing after the move from the old pin list). A vault that cannot be read leaves no secret.
    /// The pinned codes are sent to the watch again at every unlock: a duress session may have emptied it, and
    /// no record of that is kept on the phone.
    func vaultUnlocked(store: any ItemStore, isPro: Bool = false) {
        guard !frozen else { return }
        isUnlocked = true
        lastRevision = -1
        pinStore.expiresAt = nil
        guard let snapshot = try? store.load() else { pinStore.forgetSecrets(); reloadWidgets(); return }
        refresh(snapshot: snapshot)
        if isPro, !pins.isEmpty { send(snapshot: snapshot, isPro: true) }   // never empties the watch from here
    }

    /// A committed snapshot (an edit, a delete, an import, a sync run), while unlocked: pins whose item was
    /// deleted or lost its 2FA are dropped, and the widgets' secrets are rewritten (a changed secret included),
    /// so they never show a stale or deleted code. The watch is unchanged until the next pin change.
    func refresh(snapshot: StoreSnapshot) {
        guard isUnlocked, snapshot.revision >= lastRevision else { return }
        lastRevision = snapshot.revision
        let codes = WatchPins.codes(pins: pins, snapshot: snapshot)
        let live = Set(codes.map(\.id))
        if pins.contains(where: { !live.contains($0) }) {
            pins = pins.filter { live.contains($0) }
            pinStore.pinnedIDs = pins
        }
        // Travel mode (feature pack §2): hidden items stay pinned but leave the widgets until it is turned off.
        let hide = hidden(snapshot)
        pinStore.replace(hide.isEmpty ? codes : codes.filter { !hide.contains($0.id) })
        reloadWidgets()
    }

    /// Items kept off the widgets, the watch and "Copy code" on this iPhone: travel-hidden items (feature pack §2) and
    /// logins whose access rules need an owner check (§4, scan 2026-11-15 S-L2).
    @ObservationIgnored var hidden: (StoreSnapshot) -> Set<String> = { snapshot in
        AutoFillGate.codesOmitted(snapshot, travel: TravelModeBox.shared.current, today: RecordDigest.today())
    }

    /// The app went to the background unlocked: with "Forget on lock", the widgets stop showing codes at
    /// `lockDeadline` (Unix seconds; nil: already locked), even if the app is suspended or killed before the
    /// lock is processed.
    func didEnterBackground(lockDeadline: Int64?) {
        guard forgetOnLock, !frozen else { return }
        pinStore.expiresAt = Date(timeIntervalSince1970: TimeInterval(lockDeadline ?? 0))
        reloadWidgets()
    }

    /// Back in the foreground and still unlocked: the codes show again.
    func foregroundedUnlocked() {
        guard isUnlocked else { return }
        pinStore.expiresAt = nil
        reloadWidgets()
    }

    /// The vault locked (also at launch, which starts locked): with "Forget on watch" on, the widgets' store and
    /// the watch drop every secret (they get them again at the next unlock, the watch at the next pin change).
    func vaultLocked() {
        isUnlocked = false
        guard forgetOnLock, !frozen else { return }
        pinStore.forgetSecrets()
        reloadWidgets()
        if !pins.isEmpty { link.send(.forget) }
    }

    /// "Erase this iPhone's vault": the watch forgets and the pins and the widgets' secrets go.
    func vaultErased() {
        isUnlocked = false
        guard !frozen else { return }   // an erase in the second vault never touches the real vault's pins
        let had = !pins.isEmpty
        pins = []
        pinStore.removeAll()
        reloadWidgets()
        if had { link.send(.forget) }
    }
}
