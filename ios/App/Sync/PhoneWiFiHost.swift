import Foundation
import Observation
import LGKCore
import AppShared

/// Wi-Fi host mode on the iPhone (spec 2026-11-13-phone-wifi-host-design): the phone hosts exactly like the Mac
/// (`LanHost`, `HostPairingModel`, the same wire format, enrollment and `_lgksync._tcp` announcement), so any joiner
/// (desktop, Mac, iPhone, Android) can pair with it and sync to it.
///
/// * "Host Wi-Fi sync on this phone" (`AppSettings.wifiSyncOn`, off by default) on the Sync screen's Wi-Fi card.
/// * It listens only while the app is in the foreground (scene phase active) AND the vault is unlocked AND the
///   setting is on. The background, a lock or the setting turned off stops the listener and closes every open
///   connection and the pairing code; coming back starts it again. Nothing runs in the background.
/// * The address is the phone's Wi-Fi IPv4 address (`LanAddressPicker` candidates, `en0` first; never cellular,
///   VPN or loopback). The port is the last one listened on (47821 at first); when it is taken, one the system
///   picks. When the address leaves the phone the listener follows the new one (same port), like the Mac.
/// * Pro gating as on the Mac (`MacSyncScheduler`): with Pro it hosts fully; while free it hosts licence-only and
///   listens only while a pairing code is shown and for 2 minutes after it closes or after Sync now.
/// * Devices that pair with this phone are pinned without dialling them back: they connect here. The phone's own
///   host (a PC or Mac it joined) is still dialled by `SyncCoordinator`.
@MainActor
@Observable
final class PhoneWiFiHost {
    /// Windows `LICENCE_ONLY_LISTEN_SECONDS` (as `MacSyncScheduler.licenceOnlyListenSeconds`).
    nonisolated static let licenceOnlyListenSeconds: TimeInterval = 120
    /// How often the served issues are collected and the rollback witnesses flushed (the Mac's 5-minute run).
    nonisolated static let servedCheckSeconds: TimeInterval = 5 * 60

    static let toggleLabel = DeviceText.isPad ? String(localized: "ipad.sync.toggle", defaultValue: "Host Wi-Fi sync on this iPad")
        : String(localized: "Host Wi-Fi sync on this phone")
    static let offText = DeviceText.isPad ? String(localized: "ipad.sync.off", defaultValue: "Off. Other phones and computers on the same Wi-Fi can pair with this iPad and sync with it while LocalGateKeys is open and unlocked here.")
        : String(localized: "Off. Other phones and computers on the same Wi-Fi can pair with this phone and sync with it while LocalGateKeys is open and unlocked here.")
    static let noWiFiText = String(localized: "Connect this phone to Wi-Fi to host sync.")
    static let pairHint = String(localized: "Both devices must be on the same Wi-Fi.")
    static let licenceOnlyText = String(localized: "Free plan: paired devices can give this phone their Pro licence. Items sync with Pro.")
    static let licenceOnlyIdleText = String(localized: "On. On the free plan this phone listens only while a pairing code is shown and for 2 minutes after Sync now.")
    static let connectsHereText = String(localized: "Connects to this phone")
    // Mac strings, reused as they are.
    static let startingText = String(localized: "Turning on…")
    static let noPeersText = String(localized: "No devices paired yet.")
    static func listensText(_ endpoint: String) -> String { String(localized: "This phone listens on \(endpoint).") }
    static func followedText(_ endpoint: String) -> String { String(localized: "Now listening on \(endpoint) (address changed).") }
    static func removedText(_ name: String) -> String { String(localized: "\(name) was removed.") }
    /// The Remove confirmation for a device that connects to this phone (Android `sync_host_remove_confirm`).
    static func removeDeviceText(_ name: String) -> String {
        String(localized: "Remove \(name) from Wi-Fi sync? It stops syncing with this phone but keeps what it already has.")
    }

    /// The Wi-Fi host; nil when this vault cannot sync (duress session, sync unavailable): no toggle is shown then.
    private(set) var host: LanHost? = nil
    /// Issues seen while serving devices (collected every 5 minutes and after Sync now).
    private(set) var hostIssues: [SyncIssue] = []
    /// The pairing sheet (QR code, then Accept / Decline, then Undo / Keep) is shown.
    private(set) var showingQR = false
    /// Why the last Show QR code (or Remove) did not work.
    private(set) var error: String? = nil
    /// "<name> was removed." after a Remove.
    private(set) var info: String? = nil
    /// The phone has no private Wi-Fi address to listen on.
    private(set) var noWiFi = false
    /// Licence-only: the end of the listen window (nil: closed).
    private(set) var listenUntil: Date? = nil
    /// The app's scene is active (set by the app; `.inactive` changes nothing).
    private(set) var isForeground = false

    /// Called on the main actor after the host committed (a served merge, a pairing, an Undo): the lists reload.
    @ObservationIgnored var onServedChange: @MainActor () -> Void = {}
    /// The first port tried when nothing was listened on before (tests use 0: a free port).
    @ObservationIgnored var defaultPort = LanAddressPicker.defaultPort

    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let isUnlocked: @MainActor () -> Bool
    @ObservationIgnored private let hostingAllowed: @MainActor () -> Bool
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let addresses: () -> [LanInterfaceAddress]
    @ObservationIgnored private let copy: @MainActor (String) -> Void
    @ObservationIgnored private let background: any BackgroundTasking
    @ObservationIgnored private var hostTask: Task<Void, Never>? = nil
    /// The address where listening failed (port taken twice): not tried again until the address, the setting, the
    /// foreground or Pro changes.
    @ObservationIgnored private var failedAddress: String? = nil
    @ObservationIgnored private var lastServedCheck: Date? = nil
    /// Bumped by every stop: a start that finishes after it keeps nothing.
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var closed = false
    @ObservationIgnored private var timer: Timer? = nil

    /// `makeHost` builds the host over the store with `onCommit` called after each of its commits (any thread).
    init(settings: AppSettings = .shared, isUnlocked: @escaping @MainActor () -> Bool,
         hostingAllowed: @escaping @MainActor () -> Bool, now: @escaping () -> Date = Date.init,
         addresses: @escaping () -> [LanInterfaceAddress] = LanAddressPicker.currentCandidates,
         copy: @escaping @MainActor (String) -> Void = { SecretClipboard.shared.copy($0) },
         background: (any BackgroundTasking)? = nil, startTimer: Bool = true,
         makeHost: (_ onCommit: @escaping @Sendable () -> Void) -> LanHost?) {
        self.settings = settings; self.isUnlocked = isUnlocked; self.hostingAllowed = hostingAllowed
        self.now = now; self.addresses = addresses; self.copy = copy
        self.background = background ?? PlatformBackgroundTasks.make()
        let made = makeHost { [weak self] in
            Task { @MainActor [weak self] in self?.servedChanged() }
        }
        host = made
        made?.licenceOnly = !hostingAllowed()
        made?.pairing.onPaired = { [weak self] in self?.devicePaired() }
        if startTimer {
            let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.tick() } }
            RunLoop.main.add(t, forMode: .common)
            timer = t
        }
    }

    /// The live host over this unlock's store, sharing the coordinator's dependencies and hello counter source (the
    /// counters this phone sends keep increasing whichever side dials). Nil when this vault does not sync.
    static func live(store: any ItemStore, coordinator: SyncCoordinator, lock: AppLockModel, pro: ProModel) -> PhoneWiFiHost? {
        let deps = coordinator.deps
        guard deps.refusal == nil, let counters = (deps.lan as? LiveLanTransport)?.counters else { return nil }
        let controller = PhoneWiFiHost(isUnlocked: { [weak lock] in lock?.state == .unlocked },
                                       hostingAllowed: { [weak pro] in pro?.isPro ?? false },
                                       makeHost: { onCommit in
            let host = LanHost(store: CommitSignallingStore(base: store, onCommit: onCommit), deps: deps, counters: counters,
                               isUnlocked: { [weak lock] in lock?.state == .unlocked })
            host.allowsSystemPort = true
            return host
        })
        controller.onServedChange = { [weak coordinator] in coordinator?.noteServedMerge() }
        return controller
    }

    // MARK: state

    var isEnabled: Bool { settings.wifiSyncOn }
    var isListening: Bool { host?.isListening ?? false }
    /// True while this phone is free: the host runs licence-only and listens only inside the listen window.
    var licenceOnly: Bool { !hostingAllowed() }

    /// True when the host may listen: always with Pro; while free, while a pairing code is shown or the window is open.
    var mayListen: Bool {
        guard licenceOnly else { return true }
        if pairingShown { return true }
        guard let listenUntil else { return false }
        return now() < listenUntil
    }

    /// Every rule at once: not shut down, the setting on, the foreground, unlocked, and Pro or the listen window.
    var shouldListen: Bool {
        !closed && host != nil && settings.wifiSyncOn && isForeground && isUnlocked() && mayListen
    }

    /// A pairing code is shown or a device that scanned it is being confirmed or added.
    private var pairingShown: Bool {
        guard let pairing = host?.pairing, pairing.isOpen else { return false }
        return [.showing, .confirm, .adding].contains(pairing.stage)
    }

    /// The Wi-Fi card's line (`SyncPageModel.wifiText`, "this phone" for "this Mac").
    func statusText(joined: Bool, pairedCount: Int) -> String {
        guard settings.wifiSyncOn else { return Self.offText }
        guard let host, host.isListening, let endpoint = host.endpoint else {
            if noWiFi { return Self.noWiFiText }
            if let e = host?.listenError { return e }
            if licenceOnly, !mayListen { return Self.licenceOnlyIdleText }
            return Self.startingText
        }
        let shown = SyncWording.hostPort(endpoint)
        let where_ = host.addressChanged ? Self.followedText(shown) : Self.listensText(shown)
        if !joined { return String(localized: "Ready. \(where_) Show a QR code to pair your first device.") }
        return pairedCount == 0 ? String(localized: "On. \(where_) \(Self.noPeersText)") : String(localized: "On. \(where_)")
    }

    /// The listening address: the private Wi-Fi address (`en0`) first, then the other candidates in their order
    /// (private before link-local); nil without one.
    nonisolated static func preferred(_ candidates: [LanInterfaceAddress]) -> LanInterfaceAddress? {
        candidates.first { $0.interface == "en0" && !$0.address.hasPrefix("169.254.") } ?? candidates.first
    }

    // MARK: lifecycle

    /// The scene became active (true) or went to the background (false).
    func setForeground(_ on: Bool) {
        guard isForeground != on else { return }
        isForeground = on
        if on { failedAddress = nil }
        update()
    }

    /// "Host Wi-Fi sync on this phone" turned on or off.
    func setEnabled(_ on: Bool) {
        settings.wifiSyncOn = on
        failedAddress = nil
        error = nil
        if !on { hostIssues = [] }
        update()
    }

    /// Pro was gained or lost: full hosting, or licence-only while free.
    func proChanged() {
        host?.licenceOnly = licenceOnly
        if !licenceOnly { listenUntil = nil }
        failedAddress = nil
        followListenWindow()
        update()
    }

    /// The vault locked (or this unlock ended): stop for good; the host's gate refuses every later read and commit.
    func shutdown() {
        guard !closed else { return }
        closed = true
        generation += 1
        timer?.invalidate(); timer = nil
        hostTask?.cancel(); hostTask = nil
        holdForInFlightCommits()
        host?.shutdown()
        if showingQR { showingQR = false }
    }

    /// Starts or stops the listener so that it listens exactly when `shouldListen`.
    func update() {
        guard let host else { return }
        guard shouldListen else { stopListening(); return }
        if !host.isListening, hostTask == nil { start(followed: false) }
    }

    /// Every second while the app runs (tests call it): the listen window, the start/stop rules, the pairing
    /// countdowns, the announcement, the listening address and, every 5 minutes, the served issues.
    func tick() {
        guard !closed, let host else { return }
        if host.licenceOnly != licenceOnly { host.licenceOnly = licenceOnly }
        followListenWindow()
        update()
        guard shouldListen, hostTask == nil, host.isListening, let endpoint = host.endpoint else { return }
        host.pairing.tick()
        host.refreshAnnouncement()
        if !addresses().contains(where: { $0.address == endpoint.host }) {
            // The address left this phone (another Wi-Fi network): follow the new one, same port.
            holdForInFlightCommits()
            host.stopAddressLost()
            if showingQR { showingQR = false }
            start(followed: true)
            return
        }
        let t = now()
        if let last = lastServedCheck, t.timeIntervalSince(last) < Self.servedCheckSeconds { return }
        lastServedCheck = t
        Task { [weak self] in await self?.collectServed() }
    }

    /// After "Sync now": a free phone opens its listen window (a paired device can connect for a while) and the
    /// issues seen while serving are collected.
    func afterManualSync() async {
        guard !closed, settings.wifiSyncOn else { return }
        if licenceOnly { openListenWindow() }
        lastServedCheck = now()
        await collectServed()
    }

    /// The served issues, the rollback-witness flush and the announcement refresh (`LanHost.syncPeers` without
    /// dialling anyone).
    func collectServed() async {
        guard !closed, let host, host.isListening else { return }
        let issues = await host.syncPeers(dialing: false)
        guard !closed, host.isListening else { return }
        hostIssues = issues
    }

    /// Waits for a listener start in flight (tests, and Show QR code).
    func hostSettled() async { await hostTask?.value }

    // MARK: pairing (the QR sheet)

    /// "Show QR code…": listens first when needed (a free phone opens its listen window), then shows a new code.
    /// With no group yet the first accepted device creates the Wi-Fi group (`HostPairingModel.begin`).
    func showQR() async {
        error = nil; info = nil
        guard !closed, let host, settings.wifiSyncOn else { error = HostPairingModel.notListeningText; return }
        host.licenceOnly = licenceOnly
        if !host.isListening {
            failedAddress = nil
            if licenceOnly { openListenWindow() } else { update() }
            await hostTask?.value
        }
        guard !closed else { return }
        switch host.showQR() {
        case .shown: showingQR = true
        case .notListening: error = noWiFi ? Self.noWiFiText : (host.listenError ?? HostPairingModel.notListeningText)
        case .failed(let text): error = text
        }
    }

    /// "Copy code text": the one-use pairing code, copied local-only with the clipboard expiry (`SecretClipboard`).
    func copyCodeText() {
        guard let text = host?.pairing.copyCodeText() else { return }
        copy(text)
    }

    /// Close (or the sheet swiped away): the offer closes; a device just added is kept.
    func closeQR() {
        if let pairing = host?.pairing {
            if pairing.stage == .paired { pairing.keep() }
            pairing.close()
        }
        if showingQR { showingQR = false }
    }

    func decide(_ accept: Bool) {
        guard let pairing = host?.pairing, let id = pairing.request?.deviceID else { return }
        pairing.decide(accept, deviceID: id)
    }

    /// Undo: the device just added is removed again (revoked). On failure the sheet stays with the message.
    func undoPairing() {
        guard let pairing = host?.pairing else { return }
        if pairing.undo() {
            pairing.close()
            showingQR = false
        }
    }

    func keepPairing() {
        host?.pairing.keep()
        host?.pairing.close()
        showingQR = false
    }

    // MARK: remove a paired device (the Mac's `SyncPageModel.removePeer`)

    /// Remove (revoke) a device that pairs with this phone, after `removeDeviceText`. Committed through the host's
    /// gated store, so it fails once the vault locked, and the device's next connection (or a request on one in
    /// flight) is refused: the responder reads the peer list for every request. The entry stays listed (revoked)
    /// so the same id cannot come back. Free too: no Pro check. The commit reloads the lists (`onServedChange`).
    @discardableResult
    func removePeer(_ deviceID: String, name: String) -> Bool {
        error = nil; info = nil
        guard !closed, let host else { error = SyncWording.stepFailedCopy; return false }
        do {
            let snap = try host.store.load()
            guard let state = snap.sync else { return false }
            let (revoked, found) = LanPeers.revoking(deviceID, in: state)
            guard found else { return false }
            try host.store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: revoked))
        } catch {
            self.error = SyncWording.stepFailedCopy
            return false
        }
        info = Self.removedText(name)
        return true
    }

    // MARK: private

    private func start(followed: Bool) {
        guard let host else { return }
        guard let address = Self.preferred(addresses()) else {
            if !noWiFi { noWiFi = true }
            return
        }
        if noWiFi { noWiFi = false }
        guard address.address != failedAddress else { return }
        let port = savedPort ?? defaultPort
        let mine = generation
        hostTask = Task { [weak self] in
            var started = await host.start(host: address.address, port: port, followed: followed)
            if !started, port != 0, host.listenError != nil, let self, self.generation == mine, self.shouldListen {
                // The usual port is taken: a free port the system picks (published in the QR code and announcement).
                started = await host.start(host: address.address, port: 0, followed: followed)
            }
            guard let self, self.generation == mine else { return }
            self.hostTask = nil
            if started, let endpoint = host.endpoint {
                self.settings.wifiSyncEndpoint = LanAddressPicker.text(endpoint)
                self.failedAddress = nil
                self.lastServedCheck = self.now()
            } else if host.listenError != nil {
                self.failedAddress = address.address
            }
        }
    }

    /// The port last listened on (kept across restarts so joiners find this phone at the same address).
    private var savedPort: Int? {
        guard let text = settings.wifiSyncEndpoint, case .success(let e) = LanAddressPicker.validate(text) else { return nil }
        return e.port
    }

    private func stopListening() {
        guard let host else { return }
        let busy = hostTask != nil || host.isListening || host.pairing.isOpen || host.endpoint != nil
        if showingQR { showingQR = false }
        guard busy else { return }
        generation += 1
        hostTask?.cancel(); hostTask = nil
        holdForInFlightCommits()
        host.stop()   // closes every connection and the pairing code; a bind in flight is dropped
    }

    /// A served merge may be committing right now (under the store's file lock): keep the app running for one
    /// socket timeout so iOS does not suspend it holding the lock (0xdead10cc), as sync runs do.
    private func holdForInFlightCommits() {
        guard let open = host?.server?.openConnections, open > 0 else { return }
        let scope = BackgroundTaskScope(background, name: "LocalGateKeys Wi-Fi host")
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(LanListenLimits.socketSeconds * 1_000_000_000))
            scope.end()
        }
    }

    /// Licence-only: listen from now for `licenceOnlyListenSeconds` (never shortens an open window).
    func openListenWindow() {
        let until = now().addingTimeInterval(Self.licenceOnlyListenSeconds)
        if listenUntil.map({ $0 < until }) ?? true { listenUntil = until }
        update()
    }

    /// A shown pairing code keeps the window open until `licenceOnlyListenSeconds` after it closes; outside the
    /// window a free phone stops listening (`update`).
    private func followListenWindow() {
        guard licenceOnly, host != nil else { return }
        if pairingShown {
            let until = now().addingTimeInterval(Self.licenceOnlyListenSeconds)
            if listenUntil.map({ $0 < until }) ?? true { listenUntil = until }
            return
        }
        if listenUntil != nil, !mayListen { listenUntil = nil }
    }

    private func devicePaired() {
        if licenceOnly { openListenWindow() }   // the new device can connect and sync for a while
    }

    private func servedChanged() {
        guard !closed else { return }
        onServedChange()
    }
}

/// The store the phone's Wi-Fi host commits through: every successful commit (a served merge, a pairing, an Undo,
/// a witness flush) calls `onCommit` afterwards, from the committing thread.
final class CommitSignallingStore: ItemStore, @unchecked Sendable {
    let base: any ItemStore
    let onCommit: @Sendable () -> Void
    init(base: any ItemStore, onCommit: @escaping @Sendable () -> Void) { self.base = base; self.onCommit = onCommit }
    func load() throws -> StoreSnapshot { try base.load() }
    func commit(_ change: StoreChange) throws {
        try HistoryContext.$changeType.withValue(.sync) { try base.commit(change) }
        onCommit()
    }
}
