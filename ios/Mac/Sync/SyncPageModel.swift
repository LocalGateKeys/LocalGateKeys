import Foundation
import Observation
import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import LGKCore
import AppSharedMac

/// The sidebar's Sync page (Windows `SyncPage.svelte` over `app/sync.py` and `sync_view.py`): the Wi-Fi card
/// (turn on or off, address and port, Show QR code, paired devices with Remove), the Cloud folder card, Join
/// with a code (pasted `lgk-pair:` text), Messages, Sync now, and Leave sync / Reset sync behind two
/// confirmations each.
///
/// Pro (Windows `_plan_allows_sync`, iPhone rule for joining): creating cloud folder groups and changing the
/// sync key need Pro and show the upgrade sheet (`PRO_REQUIRED`); joining someone else's group by its code text
/// is free. Wi-Fi sync and Show QR code work on a free Mac in licence-only mode (`LanHost.licenceOnly`: a paired
/// device with Pro hands over its licence, nothing else is taken in or published). While free the Mac listens
/// only while a pairing code is shown and for 2 minutes after it or after Sync now (`MacSyncScheduler.mayListen`,
/// Windows licence-only mode); Show QR code starts the listener first. A licence received through
/// sync unlocks full hosting at once (`ProModel.update(from:)` after each run, then `MacSyncScheduler.proChanged`).
@MainActor
@Observable
final class SyncPageModel {
    // Windows copy ("this Mac" for "this PC").
    static let title = String(localized: "Sync")
    static let intro = String(localized: "Keep this vault in step on your phone and your other computers. Everything is encrypted before it leaves this Mac.")
    static let unavailableText = String(localized: "Sync runs while the vault is unlocked on this Mac. Unlock and try again.")
    static let wifiTitle = String(localized: "Wi-Fi (this network)")
    static let folderTitle = String(localized: "Cloud folder")
    static let joinTitle = String(localized: "Join with a code")
    static let messagesTitle = String(localized: "Messages")
    static let wifiIntro = String(localized: "This Mac's address and port on your home network. Other devices connect to it here. Only private network addresses work.")
    static let wifiOffText = String(localized: "Off. Sync with your phone or another device on the same network, without any cloud.")
    static let startingText = String(localized: "Turning on…")
    static let noPeersText = String(localized: "No devices paired yet.")
    static let pairedHeading = String(localized: "Paired devices")
    static let membersHeading = String(localized: "Devices")
    static let folderOffText = String(localized: "Off. Keep your devices in step through a folder your cloud app already syncs, such as iCloud Drive. Everything in it is encrypted.")
    static let lanOnlyFolderText = String(localized: "Not used: this vault syncs over Wi-Fi only.")
    static let lanOnlyFolderHint = String(localized: "To sync through a cloud folder too, add one to this group with a new sync password, or use the folder another device in this group already added. Your Wi-Fi pairings stay as they are.")
    nonisolated static let createIntro = String(localized: "Choose a NEW sync password for this group. Your other devices join the folder with it.")
    nonisolated static let joinFolderIntro = String(localized: "The sync password of this folder's group. It is never stored.")
    static let joinIntro = String(localized: "On the other device, choose Show QR code, then Copy code text, and paste the text here.")
    static let joinEmptyText = String(localized: "Paste the code text from the other device.")
    nonisolated static let resetHint = String(localized: " If that does not help, use Reset sync on this Mac below.")
    static let unackedDetail = String(localized: "Added by another device, not confirmed")
    static let unackedText = String(localized: "These devices were added to this sync group by another device. If they are yours, choose These are my devices. Devices you haven't confirmed lose access at the next sync key change.")
    static func confirmedText(_ n: Int) -> String { n == 1 ? String(localized: "1 device confirmed.") : String(localized: "\(n) devices confirmed.") }
    static let rotationIntro = String(localized: "Enter a NEW sync password. Your other cloud-folder devices pick up the change on their next sync; a device set up later joins with the new password.")
    static let passwordAdvice = String(localized: "Write this password down. Never reuse an earlier sync password.")
    static let mismatchText = String(localized: "The two passwords don't match.")
    static func removedText(_ name: String) -> String { String(localized: "\(name) was removed.") }

    static func removeWifiDeviceText(_ name: String) -> String {
        String(localized: "Remove \(name) from Wi-Fi sync?\n\nIt stops syncing with this Mac but keeps what it already has.\n\nWi-Fi pairing is per computer: also remove \(name) on every other computer it is paired with, or it keeps syncing with those computers.")
    }
    static func listensText(_ endpoint: String) -> String { String(localized: "This Mac listens on \(endpoint).") }
    /// The listening address followed this Mac to a new one (plan 2026-10-29-sync-ip-change).
    static func followedText(_ endpoint: String) -> String { String(localized: "Now listening on \(endpoint) (address changed).") }

    // Windows `_ACTION_LABELS`.
    static let syncNowLabel = String(localized: "Sync now"), showQRLabel = String(localized: "Show QR code…"), copyLabel = String(localized: "Copy code text")
    static let wifiOnLabel = String(localized: "Turn on Wi-Fi sync"), wifiOffLabel = String(localized: "Turn off Wi-Fi sync")
    static let createLabel = String(localized: "Create sync group…"), joinFolderLabel = String(localized: "Join a folder…"), repickLabel = String(localized: "Choose the folder again…")
    static let addFolderLabel = String(localized: "Add a cloud folder to this group…"), useFolderLabel = String(localized: "Use this group's cloud folder…")
    static let ackLabel = String(localized: "These are my devices"), leaveLabel = String(localized: "Leave sync…"), resetLabel = String(localized: "Reset sync on this Mac…")
    static let joinLabel = String(localized: "Join")

    /// A two-step confirmation (Leave, Reset) or the Remove confirmation for a Wi-Fi device.
    enum Confirmation: Equatable {
        case leave(step: Int), reset(step: Int), removePeer(id: String, name: String)
    }

    struct Device: Equatable, Identifiable {
        let id: String
        let name: String
        let detail: String
        var isSelf = false
        var unconfirmed = false
    }

    /// The folder device being removed with a new sync password (Windows rotation form).
    struct Removal: Equatable {
        let id: String
        let name: String
        let intro: String
        let keep: [String]
    }

    /// The cloud folder action waiting for its sync password, after the folder was picked.
    struct FolderForm: Equatable, Identifiable {
        enum Kind: Equatable { case create, join, add, use }
        let kind: Kind
        let bookmark: [UInt8]
        var id: [UInt8] { bookmark }
        /// Create and add set a NEW password (entered twice); join and use enter the group's one.
        var isNew: Bool { kind == .create || kind == .add }
        var title: String {
            switch kind {
            case .create: String(localized: "Create sync group")
            case .join: String(localized: "Join a folder")
            case .add: String(localized: "Add a cloud folder")
            case .use: String(localized: "Use this group's cloud folder")
            }
        }
        var intro: String { isNew ? SyncPageModel.createIntro : SyncPageModel.joinFolderIntro }
    }

    private(set) var state: SyncGroupState?
    var folderForm: FolderForm?
    /// The folder picker (`NSOpenPanel`); tests hand back a temp folder.
    @ObservationIgnored var folderPicker: @MainActor () -> URL? = { MacFolderPicker.choose() }
    /// Keyring member names (`[device id: name]`) of the stored group.
    private(set) var names: [String: String] = [:]
    var confirmation: Confirmation?
    var removal: Removal?
    var joinText = ""
    var addressText = ""
    private(set) var addressError: String?
    /// The page's own messages (copied, confirmed, refused).
    private(set) var info: String?
    private(set) var error: String?
    private(set) var working = false
    /// Shown while a pairing code is open (the QR sheet).
    var showingQR = false

    @ObservationIgnored let scheduler: MacSyncScheduler?
    @ObservationIgnored let pro: ProModel
    @ObservationIgnored private let clipboard: MacClipboard
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let onNeedsPro: (ProReason) -> Void

    init(scheduler: MacSyncScheduler?, pro: ProModel, clipboard: MacClipboard, settings: AppSettings,
         onNeedsPro: @escaping (ProReason) -> Void) {
        self.scheduler = scheduler; self.pro = pro; self.clipboard = clipboard; self.settings = settings
        self.onNeedsPro = onNeedsPro
        addressText = settings.wifiSyncEndpoint ?? ""
        reload()
    }

    var coordinator: SyncCoordinator? { scheduler?.coordinator }
    var host: LanHost? { scheduler?.host }
    var available: Bool {
        #if DEBUG
        if preview != nil { return true }
        #endif
        return coordinator != nil && coordinator?.deps.unavailableText == nil
    }
    var unavailableText: String { coordinator?.deps.unavailableText ?? Self.unavailableText }
    var wifiOn: Bool {
        #if DEBUG
        if let preview { return preview.wifiOn }
        #endif
        return settings.wifiSyncOn
    }
    var joined: Bool {
        #if DEBUG
        if preview != nil { return true }
        #endif
        return state != nil
    }

    #if DEBUG
    /// Screenshots only (`LGK_MAC_SYNC_PREVIEW`): fixed page contents instead of the live sync state.
    struct Preview {
        var wifiOn = true
        var wifiText = ""
        var peers: [Device] = []
        var members: [Device] = []
        var folderText = ""
        var lastSync = ""
        var messages: [SyncWording.IssueView] = []
        var stage: HostPairingModel.Stage = .idle
        var qrText: String?
        var offerCode: String?
        var endpoint = ""
        var countdown = ""
        var request: HostPairingModel.Request?
        var secondsLeft: Int?
    }
    var preview: Preview?
    #endif

    // MARK: pairing (the QR sheet)

    var pairingStage: HostPairingModel.Stage {
        #if DEBUG
        if let preview { return preview.stage }
        #endif
        return host?.pairing.stage ?? .idle
    }
    var qrText: String? {
        #if DEBUG
        if let preview { return preview.qrText }
        #endif
        return host?.pairing.qrText
    }
    var offerCode: String? {
        #if DEBUG
        if let preview { return preview.offerCode }
        #endif
        return host?.pairing.offerCode
    }
    var offerEndpoint: String {
        #if DEBUG
        if let preview { return preview.endpoint }
        #endif
        return host?.pairing.endpoint.map(SyncWording.hostPort) ?? ""
    }
    var countdown: String {
        #if DEBUG
        if let preview { return preview.countdown }
        #endif
        return host?.pairing.countdown ?? ""
    }
    var request: HostPairingModel.Request? {
        #if DEBUG
        if let preview { return preview.request }
        #endif
        return host?.pairing.request
    }
    var secondsLeft: Int? {
        #if DEBUG
        if let preview { return preview.secondsLeft }
        #endif
        return host?.pairing.secondsLeft
    }
    var paired: HostPairingModel.Paired? { host?.pairing.paired }
    var pairingMessage: String? { host?.pairing.message }

    // MARK: state

    /// Re-reads the stored group (after a run, a pairing, an action).
    func reload() {
        guard let coordinator else { state = nil; names = [:]; return }
        coordinator.refreshMembership()
        state = (try? coordinator.store.load())?.sync
        names = Self.memberNames(state)
        if addressText.isEmpty, let saved = settings.wifiSyncEndpoint { addressText = saved }
    }

    nonisolated static func memberNames(_ state: SyncGroupState?) -> [String: String] {
        guard let state, let bytes = state.keyring, let ring = try? CanonicalJSON.parse(bytes),
              let gk = try? GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key) else { return [:] }
        var out: [String: String] = [:]
        for (id, name) in Keyring.memberNames(ring, key: gk) {
            out[id] = name.map { SyncWording.sanitize($0) } ?? SyncWording.unnamedDevice
        }
        return out
    }

    private func name(_ id: String, fallback: String? = nil) -> String {
        if let n = names[id] { return n }
        if let fallback, !fallback.isEmpty { return SyncWording.sanitize(fallback) }
        return SyncWording.shortID(id)
    }

    /// The Wi-Fi card's paired devices (removed ones are not shown; they stay listed so they cannot come back).
    var peers: [Device] {
        #if DEBUG
        if let preview { return preview.peers }
        #endif
        return (state?.lanPeers ?? []).filter { !$0.revoked }.map { p in
            Device(id: p.deviceID, name: name(p.deviceID, fallback: p.name),
                   detail: p.endpoint.map { String(localized: "At \(SyncWording.hostPort($0))") } ?? String(localized: "Connects to this Mac"))
        }
    }

    /// The Cloud folder card's devices (keyring members), unconfirmed ones marked.
    var members: [Device] {
        #if DEBUG
        if let preview { return preview.members }
        #endif
        guard let state, state.hasFolder else { return [] }
        let unacked = Set(state.unackedMembers)
        return state.members.map { id in
            let me = id == state.deviceID
            return Device(id: id, name: name(id), detail: me ? String(localized: "This Mac") : (unacked.contains(id) ? Self.unackedDetail : ""),
                          isSelf: me, unconfirmed: !me && unacked.contains(id))
        }
    }

    /// Members added by another device that the person has not confirmed yet (`state.unackedMembers`).
    var unconfirmed: [Device] { members.filter(\.unconfirmed) }

    var wifiText: String {
        #if DEBUG
        if let preview { return preview.wifiText }
        #endif
        guard available else { return unavailableText }
        guard wifiOn else { return Self.wifiOffText }
        guard let host, host.isListening, let endpoint = host.endpoint else {
            if let error = host?.listenError { return error }
            // Free and outside the listen window: on, but not listening until pairing or Sync now.
            if let scheduler, scheduler.licenceOnly, !scheduler.mayListen { return Self.licenceOnlyIdleText }
            return Self.startingText
        }
        let where_ = host.addressChanged ? Self.followedText(SyncWording.hostPort(endpoint))
            : Self.listensText(SyncWording.hostPort(endpoint))
        if state == nil { return String(localized: "Ready. \(where_) Show a QR code to pair your first device.") }
        return peers.isEmpty ? String(localized: "On. \(where_) \(Self.noPeersText)") : String(localized: "On. \(where_)")
    }

    var folderText: String {
        #if DEBUG
        if let preview { return preview.folderText }
        #endif
        guard available else { return unavailableText }
        guard let state else { return Self.folderOffText }
        return state.hasFolder ? String(localized: "On.") : Self.lanOnlyFolderText
    }

    var lastSyncText: String {
        #if DEBUG
        if let preview { return preview.lastSync }
        #endif
        guard let at = coordinator?.lastSyncedAt else { return state == nil ? "" : String(localized: "Not synced yet") }
        let age = max(0, Int64(Date().timeIntervalSince1970) - at)
        if age < 60 { return String(localized: "Last synced just now") }
        if age < 3600 { return String(localized: "Last synced \(age / 60) min ago") }
        if age < 86400 { return String(localized: "Last synced \(age / 3600) h ago") }
        return String(localized: "Last synced \(age / 86400) d ago")
    }

    /// Messages: the coordinator's issues and the host's, deduplicated and sorted (`SyncWording.views`), with
    /// the Windows Reset hint on the ones Reset can fix.
    var messages: [SyncWording.IssueView] {
        #if DEBUG
        if let preview { return preview.messages }
        #endif
        return Self.messages(host: scheduler?.hostIssues ?? [], coordinator: coordinator?.issues ?? [], names: names,
                      ownID: state?.deviceID, folder: state?.hasFolder ?? false)
    }

    nonisolated static func messages(host: [SyncIssue], coordinator: [SyncWording.IssueView], names: [String: String] = [:],
                                     ownID: String? = nil, folder: Bool = false) -> [SyncWording.IssueView] {
        var seen = Set<String>()
        let all = coordinator + SyncWording.views(host, names: names, ownID: ownID, folder: folder)
        let unique = all.filter { seen.insert($0.text).inserted }
        let ranked = unique.enumerated().sorted { ($0.element.severity, $0.offset) < ($1.element.severity, $1.offset) }
        return ranked.map(\.element).map { v in
            v.resetOffered
                ? SyncWording.IssueView(kind: v.kind, severity: v.severity, text: v.text + resetHint, resetOffered: true)
                : v
        }
    }

    // MARK: Pro

    var hostingAllowed: Bool { pro.isPro }
    /// Free: the Wi-Fi host only takes in a licence from a paired device with Pro.
    var licenceOnly: Bool { !pro.isPro }
    static let licenceOnlyText = String(localized: "Free plan: paired devices can give this Mac their Pro licence. Items sync with Pro.")
    /// Wi-Fi sync on while free, outside the listen window (Windows licence-only mode).
    static let licenceOnlyIdleText = String(localized: "On. On the free plan this Mac listens only while a pairing code is shown and for 2 minutes after Sync now.")

    /// False (and the upgrade sheet) on the free plan.
    private func requirePro() -> Bool {
        if pro.isPro { return true }
        onNeedsPro(.sync)
        return false
    }

    // MARK: Wi-Fi

    /// Turn on Wi-Fi sync (licence-only while free) or off.
    func setWiFi(_ on: Bool) {
        error = nil; info = nil
        if on, !addressText.isEmpty, !applyAddress() { return }
        scheduler?.setWiFi(on)
    }

    /// Saves the typed address and port (and listens there when Wi-Fi sync is on).
    @discardableResult
    func applyAddress() -> Bool {
        switch LanAddressPicker.validate(addressText) {
        case .failure(let e): addressError = e.message; return false
        case .success(let endpoint):
            addressError = nil
            addressText = LanAddressPicker.text(endpoint)
            if settings.wifiSyncEndpoint != addressText || !(host?.isListening ?? false) {
                if settings.wifiSyncOn { scheduler?.setEndpoint(endpoint) } else { settings.wifiSyncEndpoint = addressText }
            }
            return true
        }
    }

    /// This Mac's private addresses (Wi-Fi and Ethernet first), offered as choices.
    var addressChoices: [String] {
        let port = host?.endpoint?.port ?? scheduler?.savedEndpoint?.port ?? LanAddressPicker.defaultPort
        return LanAddressPicker.currentCandidates().compactMap { a in
            (try? LanEndpoint(validating: a.address, port: port)).map(LanAddressPicker.text)
        }
    }

    /// "Show QR code…": a new pairing code (licence-only while free); the sheet shows it. A free Mac that is not
    /// listening (outside the listen window) starts the listener first; `pendingShow` is that start (tests await it).
    func showQR() {
        error = nil; info = nil
        guard let host else { error = HostPairingModel.notListeningText; return }
        if !host.isListening, settings.wifiSyncOn, let scheduler, scheduler.licenceOnly {
            pendingShow?.cancel()
            pendingShow = Task { [weak self] in
                _ = await scheduler.listenForPairing()
                guard let self, !Task.isCancelled else { return }
                self.pendingShow = nil
                self.presentQR(host)
            }
            return
        }
        presentQR(host)
    }

    /// The listener start a free Mac's Show QR code waits for (nil when none is going).
    @ObservationIgnored private(set) var pendingShow: Task<Void, Never>?

    private func presentQR(_ host: LanHost) {
        switch host.showQR() {
        case .shown: showingQR = true
        case .notListening: error = HostPairingModel.notListeningText
        case .failed(let text): error = text
        }
        reload()
    }

    /// "Copy code text": the one-use pairing code. Windows copies it with the clipboard's secret flags
    /// (no history, no cloud clipboard), so it is concealed here too and cleared like any copied secret.
    func copyCodeText() {
        guard let text = host?.pairing.copyCodeText() else { return }
        clipboard.copy(text, concealed: true)
    }

    func closeQR() {
        host?.pairing.close()
        showingQR = false
        reload()
    }

    func decide(_ accept: Bool) {
        guard let pairing = host?.pairing, let id = pairing.request?.deviceID else { return }
        pairing.decide(accept, deviceID: id)
    }

    func undoPairing() {
        host?.pairing.undo()
        showingQR = false
        reload()
    }

    func keepPairing() {
        host?.pairing.keep()
        host?.pairing.close()
        showingQR = false
        reload()
    }

    /// Remove (revoke) a Wi-Fi paired device, after `removeWifiDeviceText`.
    func requestRemovePeer(_ device: Device) { confirmation = .removePeer(id: device.id, name: device.name) }

    // MARK: join with a code (free)

    var verificationCode: String? { coordinator?.verificationCode.map(SyncWording.verificationCodeText) }
    var joining: Bool { coordinator?.phase == .joining }

    /// Joins the group behind pasted `lgk-pair:` text. Free: joining someone else's group needs no Pro.
    func join() async {
        error = nil; info = nil
        let text = joinText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { error = Self.joinEmptyText; return }
        guard let coordinator else { error = unavailableText; return }
        if await coordinator.joinByQR(text) { joinText = "" }
        reload()
    }

    func cancelJoin() { coordinator?.cancelJoin() }

    /// The paired host was not found at its pinned address or by discovery (Find again is offered).
    var hostNotFound: Bool { coordinator?.hostNotFound ?? false }

    /// Find again: pasted `lgk-pair:` text from the already-paired host moves its address only (keys must match).
    func findAgain() async {
        error = nil; info = nil
        let text = joinText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { error = Self.joinEmptyText; return }
        guard let coordinator else { error = unavailableText; return }
        if await coordinator.findAgain(text) { joinText = "" }
        error = coordinator.actionError; info = coordinator.actionInfo
        reload()
    }

    // MARK: sync now, leave, reset

    func syncNow() { scheduler?.syncNow() }

    var canLeave: Bool { joined }

    func requestLeave() { error = nil; info = nil; confirmation = .leave(step: 1) }
    func requestReset() { error = nil; info = nil; confirmation = .reset(step: 1) }
    func cancelConfirmation() { confirmation = nil }

    /// The text of the confirmation shown now (Windows `leave_text`, `RESET_TEXT_1/2`).
    var confirmationText: String {
        switch confirmation {
        case .leave(step: 1)?: SyncWording.onPhone(state?.hasFolder == true ? SyncWording.leaveText : SyncWording.leaveWifiText)
        case .leave?: SyncWording.onPhone(SyncWording.leaveText2)
        case .reset(step: 1)?: SyncWording.onPhone(SyncWording.resetText1)
        case .reset?: SyncWording.onPhone(SyncWording.resetText2)
        case .removePeer(_, let name)?: Self.removeWifiDeviceText(name)
        case nil: ""
        }
    }

    var confirmationButton: String {
        switch confirmation {
        case .leave?: String(localized: "Leave sync")
        case .reset?: String(localized: "Reset sync")
        case .removePeer?: String(localized: "Remove")
        case nil: ""
        }
    }

    /// The person agreed to the confirmation shown: the first step of Leave or Reset asks again; the second acts.
    func confirm() async { await confirm(confirmation) }

    /// Takes the step captured when the button was pressed: closing the alert clears `confirmation` before this runs.
    func confirm(_ shown: Confirmation?) async {
        guard let step = shown else { return }
        switch step {
        case .leave(step: 1): confirmation = .leave(step: 2)
        case .reset(step: 1): confirmation = .reset(step: 2)
        case .leave:
            confirmation = nil
            host?.pairing.close()
            await coordinator?.leave()
            finishAction()
        case .reset:
            confirmation = nil
            host?.pairing.close()
            await coordinator?.reset()
            finishAction()
        case .removePeer(let id, let name):
            confirmation = nil
            removePeer(id, name: name)
        }
    }

    private func finishAction() {
        info = coordinator?.actionInfo
        error = coordinator?.actionError
        reload()
    }

    private func removePeer(_ id: String, name: String) {
        guard let host else { return }
        do {
            let snap = try host.store.load()
            guard let state = snap.sync else { return }
            let (revoked, found) = LanPeers.revoking(id, in: state)
            guard found else { return }
            try host.store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: revoked))
            info = Self.removedText(name)
        } catch {
            self.error = SyncWording.stepFailedCopy
        }
        reload()
    }

    // MARK: cloud folder actions

    /// Create (Pro), join (free), add a folder to a Wi-Fi group (Pro), use the group's folder (free) or
    /// choose the folder again (free, no password): picks the folder, then asks for the sync password.
    /// A Mac-created group keeps syncing if Pro lapses later: only these actions check it.
    func pickFolder(_ kind: FolderForm.Kind?) async {
        error = nil; info = nil
        guard let coordinator else { error = unavailableText; return }
        if kind == .create || kind == .add { guard requirePro() else { return } }
        guard let url = folderPicker() else { return }
        let bookmark: [UInt8]
        do { bookmark = try coordinator.deps.folders.bookmark(for: url) }
        catch { self.error = SyncWording.errorText(reason: "folder-error"); return }
        guard let kind else {
            // Choose the folder again: the group is known, only the bookmark is stored.
            _ = await coordinator.repickFolder(bookmark: bookmark)
            finishAction()
            return
        }
        folderForm = FolderForm(kind: kind, bookmark: bookmark)
    }

    /// Windows `lan_removed_folder_text` (audit M9), "this Mac" for "this PC".
    nonisolated static func lanRemovedFolderText(peers: [String]) -> String {
        var text = String(localized: "A Wi-Fi device was removed from this group, and it still knows the current sync key. So the cloud folder gets a NEW key instead, and the removed device cannot read it.")
        if !peers.isEmpty {
            text += String(localized: "\n\nYour other paired devices can't receive a new key over Wi-Fi: \(peers.joined(separator: ", ")). Afterwards pair each of them again (leave sync there, then scan a new QR code), or use Join a folder there with the new sync password. Until then they don't sync with this Mac.")
        }
        return text + "\n\n" + String(localized: "Continue?")
    }
    static let newKeyTitle = String(localized: "New sync key")

    /// Set while the "New sync key" confirmation is shown (add a folder after a Wi-Fi device was removed).
    var freshKeyText: String?

    /// The sync password for the picked folder (`again` only for a new password). Adding a folder to a group
    /// with a removed Wi-Fi device first asks for a new key; the sheet calls again with `freshKeyConfirmed`.
    @discardableResult
    func submitFolder(password: String, again: String = "", freshKeyConfirmed: Bool = false) async -> Bool {
        guard let form = folderForm, let coordinator else { return false }
        error = nil; info = nil
        if form.isNew {
            guard password == again else { error = Self.mismatchText; return false }
            guard requirePro() else { return false }
        }
        let freshKey = form.kind == .add && (state?.lanPeers.contains(where: \.revoked) ?? false)
        if freshKey && !freshKeyConfirmed {
            freshKeyText = Self.lanRemovedFolderText(peers: peers.map(\.name))
            return false
        }
        freshKeyText = nil
        working = true
        defer { working = false }
        let ok = form.isNew
            ? await coordinator.createFolder(bookmark: form.bookmark, password: password, add: form.kind == .add,
                                             freshKey: freshKey)
            : await coordinator.joinFolder(bookmark: form.bookmark, password: password)
        if ok { folderForm = nil }
        finishAction()
        return ok
    }

    func cancelFolder() { folderForm = nil; freshKeyText = nil }

    // MARK: cloud folder members

    /// The group's folder for actions on its keyring (the stored bookmark).
    private func folderSync() throws -> FolderSync {
        guard let coordinator else { throw SyncActionError("not-joined") }
        return try Self.folderSync(coordinator.deps)
    }

    nonisolated private static func folderSync(_ deps: SyncDependencies) throws -> FolderSync {
        guard let bookmark = try deps.keychain.readSlot(.folderBookmark) else {
            throw FolderSyncError("folder-missing", String(localized: "no folder chosen on this device"))
        }
        let (folder, refreshed) = try deps.folders.open(bookmark: bookmark)
        if let refreshed { try? deps.keychain.writeSlot(.folderBookmark, refreshed) }
        return try FolderSync(access: folder, installID: try deps.keychain.installID(random: deps.random),
                              licenseKeys: deps.licenseKeys, pairedKeys: SyncCoordinator.pairedKeys(deps),
                              attachmentBlobs: deps.attachmentBlobs)
    }

    /// "These are my devices": the members shown as unconfirmed stop being unconfirmed (only those ids, so one
    /// that arrived after the page was drawn stays unconfirmed).
    func confirmMembers() {
        error = nil; info = nil
        let ids = unconfirmed.map(\.id)
        guard !ids.isEmpty, let coordinator else { return }
        do {
            let n = try folderSync().acknowledgeMembers(store: coordinator.store, ids)
            info = Self.confirmedText(n)
        } catch {
            self.error = SyncCoordinator.text(for: error)
        }
        reload()
    }

    /// Who keeps the group key when `removing` is removed (Windows `rotation_plan`, audit M10): the confirmed
    /// members other than this Mac; unconfirmed members are left out and lose access.
    nonisolated static func keepList(_ state: SyncGroupState, removing: Set<String>) -> [String] {
        let unacked = Set(state.unackedMembers)
        return state.members.filter { $0 != state.deviceID && !removing.contains($0) && !unacked.contains($0) }
    }

    /// Windows `rotation_plan` text.
    nonisolated static func keepText(_ state: SyncGroupState, removing: Set<String>, names: [String: String]) -> String {
        func shown(_ id: String) -> String { names[id] ?? SyncWording.shortID(id) }
        let keep = keepList(state, removing: removing).map(shown) + [String(localized: "this Mac")]
        var text = String(localized: "The new sync key goes only to: \(keep.joined(separator: ", ")).")
        let lose = state.members.filter { Set(state.unackedMembers).contains($0) && !removing.contains($0) && $0 != state.deviceID }
        if !lose.isEmpty {
            text += String(localized: " Not confirmed, so they lose access: \(lose.map(shown).joined(separator: ", ")). To keep one, cancel and choose These are my devices first.")
        }
        return text
    }

    /// "Remove a device…" on the Cloud folder card: a new sync key and password without it (Pro).
    func requestRemoveMember(_ device: Device) {
        error = nil; info = nil
        guard let state, !device.isSelf else { return }
        guard requirePro() else { return }
        let gone: Set<String> = [device.id]
        var intro = Self.rotationIntro
        let others = peers.filter { $0.id != device.id }
        if !others.isEmpty {
            intro += String(localized: "\n\nDevices paired by QR code can't follow a password change and must be paired again afterwards: \(others.map(\.name).joined(separator: ", ")).")
        }
        intro += "\n\n" + Self.keepText(state, removing: gone, names: names)
        removal = Removal(id: device.id, name: device.name, intro: intro, keep: Self.keepList(state, removing: gone))
    }

    /// Removes the device with the new password, wrapping the new key only to the confirmed members (`keep`).
    func removeMember(password: String, again: String) async -> Bool {
        guard let removal, let coordinator else { return false }
        guard password == again else { error = Self.mismatchText; return false }
        guard requirePro() else { return false }
        error = nil; working = true
        defer { working = false }
        do {
            let store = coordinator.store, deps = coordinator.deps
            let id = removal.id, keep = removal.keep
            try await Task.detached {
                let fs = try Self.folderSync(deps)
                _ = try fs.rotate(store: store, newPassword: password, remove: [id], keep: keep, random: deps.random, clock: deps.clock)
            }.value
            info = Self.removedText(removal.name)
            self.removal = nil
            reload()
            return true
        } catch {
            self.error = SyncCoordinator.text(for: error)
            return false
        }
    }

    // MARK: QR image

    /// The pairing QR code (CoreImage, medium error correction), each module a whole number of pixels.
    nonisolated static func qrImage(_ text: String, side: CGFloat = 260) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let modules = output.extent.width + 8   // a 4-module quiet zone on each side
        let scale = max(1, (side * 2 / modules).rounded(.down))   // drawn at 2x for Retina
        let padded = output.transformed(by: CGAffineTransform(translationX: 4, y: 4))
            .composited(over: CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: modules, height: modules)))
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = CIContext().createCGImage(padded, from: padded.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: padded.extent.width / 2, height: padded.extent.height / 2))
    }
}

#if DEBUG
/// `LGK_MAC_SYNC_PREVIEW=page|confirm`: fixed Sync page contents for screenshots (made-up devices and codes).
@MainActor
enum SyncPagePreview {
    static func make(_ kind: String) -> SyncPageModel.Preview {
        var p = SyncPageModel.Preview()
        p.wifiText = "On. " + SyncPageModel.listensText("192.168.1.20:47821")
        p.peers = [SyncPageModel.Device(id: "p1", name: "iPhone", detail: "Connects to this Mac"),
                   SyncPageModel.Device(id: "p2", name: "Windows PC", detail: "At 192.168.1.31:47821")]
        p.folderText = SyncPageModel.lanOnlyFolderText
        p.lastSync = "Last synced 2 min ago"
        p.messages = SyncPageModel.messages(host: [SyncIssue("unreachable", "192.168.1.31:47821")], coordinator: [])
        p.endpoint = "192.168.1.20:47821"
        p.offerCode = "4821 7730"
        p.qrText = "lgk-pair:preview-only-not-a-real-offer-0000000000000000000000000000000000000000"
        p.countdown = HostPairingModel.countdownText(104)
        if kind == "confirm" {
            p.stage = .confirm
            let code = HostPairingModel.formatCode("482913")
            p.request = HostPairingModel.Request(deviceID: "p3", name: "Anna's iPhone", code: code,
                                                 fingerprint: HostPairingModel.fingerprintText("3fa29c0be4d17a65"),
                                                 message: HostPairingModel.confirmText(name: "Anna's iPhone", code: code))
            p.secondsLeft = 52
        }
        return p
    }
}
#endif
