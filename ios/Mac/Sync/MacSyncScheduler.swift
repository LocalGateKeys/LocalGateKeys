import Foundation
import Observation
import LGKCore
import AppSharedMac

/// When the Mac syncs (Windows schedule): once at unlock, every 5 minutes while unlocked and 10 s after the
/// last local edit; nothing while locked. Each unlock gets a new coordinator over `lock.store` and, when
/// sync is available, a Wi-Fi host sharing the coordinator's hello counter source. Locking shuts both down:
/// the coordinator's gate closes (a run in flight commits nothing more), the listener stops.
///
/// Commits made by sync itself (`SyncSourceStore`) are not edits, so a merge never schedules another run;
/// a merge served to a peer while no run is going still bumps `syncRevision`, so the window reloads.
///
/// Wi-Fi hosting follows `AppSettings.wifiSyncOn` and listens on the saved endpoint (or the suggested one).
/// When the listening address leaves this Mac (an interface change) the host stops with
/// `LanHost.stoppedText`; it starts again by itself only when that same saved address comes back (or when
/// the person turns Wi-Fi sync on again). A listen failure (port taken) is never retried by the timer.
///
/// A free Mac (licence-only, Windows `SyncService(licence_only=True)`) listens only inside a listen window:
/// while a pairing code is shown and for `licenceOnlyListenSeconds` after it closes, and for that long after a
/// person-started Sync now (`syncNow`, also run after a device was added). Outside the window the host is
/// stopped, even with Wi-Fi sync on; the timer stops it when the window ends.
@MainActor
@Observable
final class MacSyncScheduler {
    static let intervalSeconds: TimeInterval = 5 * 60
    static let editDelaySeconds: TimeInterval = 10
    nonisolated static let editDelayNanos: UInt64 = 10_000_000_000

    enum Trigger: Equatable { case unlock, interval, localEdit, manual }

    /// Windows `LICENCE_ONLY_LISTEN_SECONDS`: how long a free Mac keeps listening after Sync now or a pairing code.
    nonisolated static let licenceOnlyListenSeconds: TimeInterval = 120

    /// Bumped after each completed run, and after a merge served to a peer outside a run: the window
    /// reloads its lists, prunes reminders and collections and updates Pro on every change.
    private(set) var syncRevision = 0
    /// Issues from the host's last run (peers dialled and served), shown by the Sync page.
    private(set) var hostIssues: [SyncIssue] = []
    private(set) var coordinator: SyncCoordinator?
    private(set) var host: LanHost?
    /// Runs started, per trigger (tests and diagnostics).
    @ObservationIgnored private(set) var triggers: [Trigger] = []
    /// Pro gating (Windows `_plan_allows_sync`): full Wi-Fi hosting needs Pro. A free Mac still joins someone
    /// else's group and syncs as its member, and its host runs licence-only (pairing works, only a licence state is
    /// taken in, nothing is published or dialled), so a paired device with Pro can hand it a licence. It listens
    /// only inside the listen window (`mayListen`). `proChanged()` re-reads it.
    @ObservationIgnored var hostingAllowed: @MainActor () -> Bool = { true }

    @ObservationIgnored private weak var lock: MacLockModel?
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let makeCoordinator: @MainActor (MacLockModel) -> SyncCoordinator?
    @ObservationIgnored private let makeHost: @MainActor (MacLockModel, SyncCoordinator) -> LanHost?
    @ObservationIgnored private let addresses: () -> [LanInterfaceAddress]
    @ObservationIgnored private var lastRunAt: Date?
    @ObservationIgnored private var editAt: Date?
    @ObservationIgnored private var runTask: Task<Void, Never>?
    @ObservationIgnored private var again: Trigger?
    @ObservationIgnored private var hostTask: Task<Void, Never>?
    /// Licence-only: the end of the listen window (nil: closed). Observed, so the Sync page's text follows it.
    private(set) var listenUntil: Date?
    @ObservationIgnored private var addressLost = false
    /// Bumped by every lock: a run or start that finishes under a newer generation keeps nothing.
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var timer: Timer?

    init(lock: MacLockModel, settings: AppSettings, now: @escaping () -> Date = Date.init,
         makeCoordinator: @escaping @MainActor (MacLockModel) -> SyncCoordinator? = { MacSyncEnvironment.makeCoordinator(lock: $0) },
         makeHost: @escaping @MainActor (MacLockModel, SyncCoordinator) -> LanHost? = MacSyncScheduler.liveHost,
         addresses: @escaping () -> [LanInterfaceAddress] = LanAddressPicker.currentCandidates,
         startTimer: Bool = true) {
        self.lock = lock; self.settings = settings; self.now = now
        self.makeCoordinator = makeCoordinator; self.makeHost = makeHost; self.addresses = addresses
        lock.onUnlock.append { [weak self] in self?.unlocked() }
        lock.onLock.append { [weak self] in self?.locked() }
        lock.onCommit.append { [weak self] fromSync in self?.committed(fromSync: fromSync) }
        if startTimer {
            let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.tick() } }
            RunLoop.main.add(t, forMode: .common)
            timer = t
        }
        if lock.state == .unlocked { unlocked() }
    }

    isolated deinit { timer?.invalidate() }

    /// The live host: none when sync is unavailable in this build; else over the coordinator's dependencies
    /// and its hello counter source.
    static func liveHost(lock: MacLockModel, coordinator: SyncCoordinator) -> LanHost? {
        guard coordinator.deps.unavailableText == nil,
              let counters = MacSyncEnvironment.helloCounters(coordinator.deps) else { return nil }
        return LanHost.make(lock: lock, deps: coordinator.deps, counters: counters)
    }

    private var isUnlocked: Bool { lock?.state == .unlocked }

    // MARK: lock and unlock

    private func unlocked() {
        guard isUnlocked, coordinator == nil, let lock else { return }
        guard let coordinator = makeCoordinator(lock) else { return }
        self.coordinator = coordinator
        host = makeHost(lock, coordinator)
        host?.licenceOnly = !hostingAllowed()
        host?.pairing.onPaired = { [weak self] in self?.syncNow() }   // a device just added: sync with it
        addressLost = false
        startHostIfWanted()
        request(.unlock)
    }

    private func locked() {
        generation += 1
        coordinator?.shutdown()
        host?.shutdown()
        hostTask?.cancel(); hostTask = nil
        runTask = nil; again = nil
        coordinator = nil; host = nil
        lastRunAt = nil; editAt = nil; listenUntil = nil
        hostIssues = []
    }

    private func committed(fromSync: Bool) {
        guard isUnlocked, coordinator != nil else { return }
        if fromSync {
            // A merge a peer pushed to this Mac's host: show it now (a run reloads when it completes).
            if runTask == nil { syncRevision += 1 }
        } else {
            editAt = now()
        }
    }

    // MARK: schedule

    /// Every second while the app runs (tests call it with a fake clock): the edit delay, the 5-minute
    /// interval, the pairing sheet's countdowns and the listening address.
    func tick() {
        guard isUnlocked, coordinator != nil else { return }
        if let host, host.isListening { host.pairing.tick(); host.refreshAnnouncement() }
        followListenWindow()
        checkAddress()
        let t = now()
        if let editAt, t.timeIntervalSince(editAt) >= Self.editDelaySeconds { request(.localEdit) }
        else if let lastRunAt, t.timeIntervalSince(lastRunAt) >= Self.intervalSeconds { request(.interval) }
    }

    /// "Sync now" (and the run after a device was added): on a free Mac it also opens the listen window, so a
    /// paired phone can connect for a while.
    func syncNow() {
        guard isUnlocked, coordinator != nil else { return }
        if licenceOnly { openListenWindow() }
        request(.manual)
    }

    /// Starts a run now, or one more right after the run in flight.
    private func request(_ trigger: Trigger) {
        guard isUnlocked, coordinator != nil else { return }
        editAt = nil
        lastRunAt = now()
        if runTask != nil { again = trigger; return }
        let mine = generation
        runTask = Task { [weak self] in
            var next: Trigger? = trigger
            while let t = next, let self, self.generation == mine {
                self.again = nil
                await self.run(t, generation: mine)
                next = self.generation == mine ? self.again : nil
            }
            if let self, self.generation == mine { self.runTask = nil }
        }
    }

    /// Waits for the run in flight and any run queued behind it (tests).
    func settled() async {
        while let task = runTask { await task.value; if runTask == nil { break } }
    }

    private func run(_ trigger: Trigger, generation mine: Int) async {
        guard let coordinator else { return }
        triggers.append(trigger)
        host?.licenceOnly = !hostingAllowed()
        await coordinator.sync(trigger == .localEdit ? .localEdit : .manual)
        guard generation == mine, isUnlocked else { return }   // locked mid-run: nothing more
        if let host, host.isListening {
            let issues = await host.syncPeers()
            guard generation == mine, isUnlocked else { return }
            if host.isListening { hostIssues = issues }   // turned off meanwhile: nothing to show
        }
        syncRevision += 1
    }

    // MARK: Wi-Fi hosting

    #if DEBUG
    /// Tests only: a saved 127.0.0.1 endpoint counts (production listens on private LAN addresses only).
    @ObservationIgnored var allowsLoopbackForTests = false
    #endif
    private var allowLoopback: Bool {
        #if DEBUG
        allowsLoopbackForTests
        #else
        false
        #endif
    }

    /// The saved listening endpoint, if it is a valid one.
    var savedEndpoint: LanEndpoint? {
        guard let text = settings.wifiSyncEndpoint,
              case .success(let e) = LanAddressPicker.validate(text, allowLoopback: allowLoopback) else { return nil }
        return e
    }

    /// Wi-Fi sync turned on or off (the Sync page); on listens at once while unlocked.
    func setWiFi(_ on: Bool) {
        settings.wifiSyncOn = on
        addressLost = false
        if on { startHostIfWanted(force: true) } else { hostTask?.cancel(); hostTask = nil; host?.stop(); hostIssues = [] }
    }

    /// A new address or port chosen: saved, and listened on when Wi-Fi sync is on.
    func setEndpoint(_ endpoint: LanEndpoint) {
        settings.wifiSyncEndpoint = LanAddressPicker.text(endpoint)
        addressLost = false
        if settings.wifiSyncOn { startHostIfWanted(force: true) }
    }

    /// Pro was gained (a purchase, or a desktop licence received through sync) or lost: full hosting, or
    /// licence-only hosting while free.
    func proChanged() {
        host?.licenceOnly = !hostingAllowed()
        if !licenceOnly { listenUntil = nil }
        followListenWindow()
        startHostIfWanted()
    }

    // MARK: licence-only listen window

    /// True while this Mac is free: its host runs licence-only and listens only inside the listen window.
    var licenceOnly: Bool { !hostingAllowed() }

    /// True when the host may listen: always with Pro; while free, while a pairing code is shown or the window is open.
    var mayListen: Bool {
        guard licenceOnly else { return true }
        if pairingShown { return true }
        guard let listenUntil else { return false }
        return now() < listenUntil
    }

    /// A pairing code is shown or a device that scanned it is being confirmed or added.
    private var pairingShown: Bool {
        guard let pairing = host?.pairing, pairing.isOpen else { return false }
        return [.showing, .confirm, .adding].contains(pairing.stage)
    }

    /// Licence-only: listen from now for `licenceOnlyListenSeconds` (never shortens an open window).
    private func openListenWindow() {
        let until = now().addingTimeInterval(Self.licenceOnlyListenSeconds)
        if listenUntil.map({ $0 < until }) ?? true { listenUntil = until }
        startHostIfWanted()
    }

    /// Every tick and Pro change: a shown pairing code keeps the window open until `licenceOnlyListenSeconds`
    /// after it closes; a free host outside the window stops (quietly: no error text, Wi-Fi sync stays on).
    private func followListenWindow() {
        guard licenceOnly, let host else { return }
        if pairingShown {
            let until = now().addingTimeInterval(Self.licenceOnlyListenSeconds)
            if listenUntil.map({ $0 < until }) ?? true { listenUntil = until }
            return
        }
        guard !mayListen else { return }
        listenUntil = nil
        if host.isListening || hostTask != nil {
            hostTask?.cancel(); hostTask = nil
            host.stop()
        }
    }

    /// "Show QR code" on a free Mac that is not listening: opens the listen window and waits for the listener,
    /// so the code can be shown. True when the host listens.
    func listenForPairing() async -> Bool {
        guard settings.wifiSyncOn, isUnlocked, let host else { return false }
        if host.isListening { return true }
        if licenceOnly { openListenWindow() } else { startHostIfWanted() }
        await hostTask?.value
        return host.isListening
    }

    private func startHostIfWanted(force: Bool = false) {
        guard settings.wifiSyncOn, isUnlocked, mayListen, let host, hostTask == nil || force else { return }
        if host.isListening && !force { return }
        guard let endpoint = LanAddressPicker.suggestion(current: savedEndpoint, candidates: addresses()) else { return }
        let mine = generation
        hostTask?.cancel()
        hostTask = Task { [weak self] in
            let started = await host.start(endpoint)
            guard let self, self.generation == mine else { return }
            if started { self.settings.wifiSyncEndpoint = LanAddressPicker.text(endpoint) }
            self.hostTask = nil
        }
    }

    /// Follows this Mac's address when the listening one has gone and exactly one obvious new one exists (desktop
    /// `AddressFollower`: same port, setting updated); otherwise stops, and starts again when the saved one is back.
    private func checkAddress() {
        guard settings.wifiSyncOn, let host, hostTask == nil else { return }
        if host.isListening, let endpoint = host.endpoint {
            let current = addresses()
            guard !current.contains(where: { $0.address == endpoint.host }) else { return }
            host.stopAddressLost()
            addressLost = true
            if let moved = LanAddressPicker.followed(stored: endpoint, candidates: current) { follow(host, to: moved) }
        } else if addressLost, let saved = savedEndpoint {
            let current = addresses()
            if current.contains(where: { $0.address == saved.host }) {
                addressLost = false
                startHostIfWanted()
            } else if let moved = LanAddressPicker.followed(stored: saved, candidates: current) {
                follow(host, to: moved)
            }
        }
    }

    /// Listens on `endpoint` (this Mac's new address) and saves it once listening.
    private func follow(_ host: LanHost, to endpoint: LanEndpoint) {
        guard mayListen else { return }   // free and outside the listen window: the next window listens there
        let mine = generation
        hostTask = Task { [weak self] in
            let started = await host.start(endpoint, followed: true)
            guard let self, self.generation == mine else { return }
            if started {
                self.settings.wifiSyncEndpoint = LanAddressPicker.text(endpoint)
                self.addressLost = false
            }
            self.hostTask = nil
        }
    }

    /// Waits for a listener start in flight (tests).
    func hostSettled() async { await hostTask?.value }
}
