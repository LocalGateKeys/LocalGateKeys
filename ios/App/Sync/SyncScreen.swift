import SwiftUI
import LocalAuthentication
import AppShared

/// Sync: Wi-Fi card (pair by QR), Cloud folder card (join or attach), status, issues with the desktop's
/// wording, Leave and Reset (two confirmations each).
struct SyncScreen: View {
    let coordinator: SyncCoordinator
    /// False when shown as the Sync tab (no Done button).
    var showsDone = true
    /// Removing devices needs Pro (Windows `_plan_allows_sync`); nil: the upgrade sheet cannot be shown.
    var pro: ProModel? = nil
    /// Wi-Fi host mode (this phone listens; spec 2026-11-13-phone-wifi-host-design); nil: no host rows.
    var wifiHost: PhoneWiFiHost? = nil
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    private enum Sheet: String, Identifiable { case scanner, paste, picker, password, createPicker, createPassword, findAgain; var id: String { rawValue } }
    private enum Confirm: Equatable { case leave1, leave2, reset1, reset2, rollback, freshKey, removePeer(id: String, name: String) }

    @State private var sheet: Sheet?
    @State private var confirm: Confirm?
    @State private var pastedCode = ""
    @State private var pickedBookmark: [UInt8]?
    @State private var password = ""
    /// The second entry of a new sync password (Start a new folder).
    @State private var passwordAgain = ""
    /// The picked folder is added to this device's Wi-Fi group (Add a cloud folder to this group) instead of starting a new group.
    @State private var addingFolder = false
    /// The new sync password waiting for the "New sync key" confirmation (a Wi-Fi device was removed before).
    @State private var freshKeyPassword: String?
    @State private var localError: String?
    /// Remove a device (false) or I lost a device (true): choosing the devices.
    @State private var choosing: Choosing?
    /// The removal waiting for its new sync password.
    @State private var removal: DeviceRemoval.Plan?
    @State private var showChecklist = false
    @State private var showUpgrade = false

    private struct Choosing: Identifiable { let lost: Bool; var id: Bool { lost } }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                List {
                    statusSection
                    wifiSection
                    folderSection
                    if !coordinator.issues.isEmpty { issuesSection }
                    if coordinator.membership.joined { leaveSection }
                }
                // A refused join (often reported after the scanner sheet closes) is always brought into view.
                .onChange(of: coordinator.actionError) { _, error in
                    if error != nil { withAnimation { proxy.scrollTo(Self.statusID, anchor: .top) } }
                }
                .onChange(of: localError) { _, error in
                    if error != nil { withAnimation { proxy.scrollTo(Self.statusID, anchor: .top) } }
                }
                .scrollContentBackground(.hidden)
                .lgkAuroraBackground()
                .navigationTitle("Sync")
                .toolbar { if showsDone { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } } }
                .refreshable { await coordinator.sync(.pullToRefresh); await wifiHost?.afterManualSync() }
                .onAppear { coordinator.refreshMembership() }
                .sheet(isPresented: Binding(get: { wifiHost?.showingQR ?? false },
                                            set: { if !$0 { wifiHost?.closeQR() } })) {
                    if let wifiHost { PhoneHostQRSheet(host: wifiHost) }
                }
                .sheet(item: $sheet) { which in sheetView(which) }
                .sheet(item: $choosing) { mode in
                    RemoveDevicesChooser(lost: mode.lost, candidates: candidates, onContinue: { ids in
                        choosing = nil
                        let plan = makePlan(ids, lost: mode.lost)
                        DispatchQueue.main.async { removal = plan }
                    }, onCancel: { choosing = nil })
                }
                .sheet(item: $removal) { plan in
                    RemoveDevicesPasswordSheet(coordinator: coordinator, plan: plan) { removed in
                        removal = nil
                        if removed && plan.lost { DispatchQueue.main.async { showChecklist = true } }
                    }
                }
                .sheet(isPresented: $showChecklist) { LostDeviceChecklist { showChecklist = false } }
                .sheet(isPresented: $showUpgrade) { if let pro { UpgradeView(pro: pro) } }
                .alert(confirmTitle, isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } })) {
                    confirmButtons
                } message: { Text(confirmMessage) }
            }
        }
    }

    private static let statusID = "sync-status"

    // MARK: sections

    private var statusSection: some View {
        Section {
            HStack {
                if coordinator.isBusy { ProgressView().padding(.trailing, 4) }
                Text(statusText).foregroundStyle(Palette.text)
            }
            .id(Self.statusID)
            if coordinator.conflictCopies > 0 {
                Text("\(coordinator.conflictCopies) conflict copies made since you unlocked.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if coordinator.connecting != nil {
                Button("Cancel", role: .cancel) { coordinator.cancelJoin() }
            }
            if let code = coordinator.verificationCode {
                // QR join waiting for Accept on the inviting device, which shows the same code.
                VStack(alignment: .leading, spacing: 6) {
                    Text(SyncWording.verificationCodeText(code))
                        .font(.system(.largeTitle, design: .monospaced).weight(.semibold))
                        .foregroundStyle(Palette.text)
                        .accessibilityLabel("Verification code \(code.map { String($0) }.joined(separator: " "))")
                    Text(SyncWording.verificationCodeHint)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let e = coordinator.actionError ?? localError {
                Text(e).foregroundStyle(Palette.danger).fixedSize(horizontal: false, vertical: true)
                if coordinator.actionError != nil && coordinator.actionOffersSettings {
                    Button("Open Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    }
                }
            }
            if let i = coordinator.actionInfo { Text(i).foregroundStyle(Palette.success) }
            if coordinator.membership.joined {
                Button("Sync now") {
                    Task { await coordinator.syncNow(); await wifiHost?.afterManualSync() }
                }.disabled(coordinator.isBusy)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var statusText: String {
        switch coordinator.phase {
        case .syncing: return String(localized: "Syncing…")
        case .joining:
            if let ep = coordinator.connecting { return String(localized: "Connecting to \(SyncWording.hostPort(ep))…") }
            if coordinator.verificationCode != nil { return String(localized: "Waiting for Accept on the other device…") }
            return String(localized: "Joining…")
        case .idle:
            guard coordinator.membership.joined else { return DeviceText.isPad ? String(localized: "ipad.sync.notSetUp", defaultValue: "Sync is not set up on this iPad.") : String(localized: "Sync is not set up on this iPhone.") }
            guard let at = coordinator.lastSyncedAt else { return String(localized: "Not synced since you unlocked.") }
            return String(localized: "Last synced \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .omitted, time: .shortened)).")
        }
    }

    private var wifiSection: some View {
        Section("Wi-Fi") {
            if coordinator.membership.joined, let own = coordinator.membership.deviceID, !own.isEmpty {
                Text(SyncWording.thisDevice(name: coordinator.membership.names[own], id: own)).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if let peer = coordinator.membership.peer {
                Text("Paired with \(SyncWording.shortID(peer.deviceID))").foregroundStyle(Palette.text)
                if let ep = peer.endpoint { Text(SyncWording.peerAddress(host: ep.host, port: Int(ep.port))).font(.footnote).foregroundStyle(Palette.secondaryText) }
                Text("Syncs when both are on the same Wi-Fi and LocalGateKeys is unlocked on the other device.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                if coordinator.hostNotFound {
                    Text(SyncWording.hostNotFoundTitle).foregroundStyle(Palette.warning)
                    Text(SyncWording.findAgainHint).font(.footnote).foregroundStyle(Palette.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                    Button(SyncWording.findAgainAction) { sheet = .findAgain }.disabled(coordinator.isBusy)
                }
            } else if !coordinator.membership.joined {
                Text("On your PC choose Show QR code on the Wi-Fi card, then scan it here within 120 seconds.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Scan QR code") { sheet = .scanner }.disabled(coordinator.isBusy)
                Button("Paste code text") { pastedCode = ""; sheet = .paste }.disabled(coordinator.isBusy)
            } else if coordinator.membership.hasFolder && coordinator.membership.wifiPeers.isEmpty {
                Text(DeviceText.isPad ? String(localized: "ipad.syncScreen.syncsThroughCloudFolder", defaultValue: "This iPad syncs through the cloud folder only.") : String(localized: "This iPhone syncs through the cloud folder only.")).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if let wifiHost { hostRows(wifiHost) }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Wi-Fi host mode: the setting, what the listener is doing, Show QR code, the devices that pair with this
    /// phone and the issues seen while serving them.
    @ViewBuilder private func hostRows(_ host: PhoneWiFiHost) -> some View {
        let hosted = hostedPeers
        Toggle(PhoneWiFiHost.toggleLabel, isOn: Binding(get: { host.isEnabled }, set: { host.setEnabled($0) }))
            .foregroundStyle(Palette.text)
        Text(host.statusText(joined: coordinator.membership.joined, pairedCount: hosted.count))
            .font(.footnote).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
        if host.isEnabled {
            if host.licenceOnly {
                Text(PhoneWiFiHost.licenceOnlyText).font(.footnote).foregroundStyle(Palette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button(String(localized: "Show QR code…")) { Task { await host.showQR() } }
        }
        if let e = host.error {
            Text(e).foregroundStyle(Palette.danger).fixedSize(horizontal: false, vertical: true)
        }
        if let i = host.info { Text(i).foregroundStyle(Palette.success) }
        // Listed (and removable) also while hosting is off or free, like the Mac and Android.
        if !hosted.isEmpty {
            Text("Paired devices").font(.footnote.weight(.semibold)).foregroundStyle(Palette.secondaryText)
            ForEach(hosted, id: \.deviceID) { p in
                let name = SyncWording.labeled(p.name, p.deviceID)
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(name).foregroundStyle(Palette.text)
                        Text(PhoneWiFiHost.connectsHereText).font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                    Spacer()
                    Button("Remove…", role: .destructive) { confirm = .removePeer(id: p.deviceID, name: name) }
                        .buttonStyle(.borderless)
                }
            }
        }
        if host.isEnabled {
            ForEach(SyncWording.views(host.hostIssues, ownID: coordinator.membership.deviceID,
                                      folder: coordinator.membership.hasFolder)) { issue in
                Label(issue.text, systemImage: icon(issue.severity)).foregroundStyle(color(issue.severity))
            }
        }
    }

    /// The devices pinned on this phone (they connect to it; a joining phone pins none).
    private var hostedPeers: [LanPeer] {
        (coordinator.groupState()?.lanPeers ?? []).filter { !$0.revoked }
    }

    private var folderSection: some View {
        Section("Cloud folder") {
            let m = coordinator.membership
            if m.hasFolder {
                Text(m.hasBookmark ? String(localized: "Syncing through the cloud folder.") : (DeviceText.isPad ? String(localized: "ipad.syncScreen.chooseSyncFolderAgain", defaultValue: "Choose the sync folder again on this iPad.") : String(localized: "Choose the sync folder again on this iPhone.")))
                    .foregroundStyle(m.hasBookmark ? Palette.text : Palette.warning)
                Button("Choose the folder again…") { sheet = .picker }.disabled(coordinator.isBusy)
                folderMembers
            } else if m.joined {
                Text("To sync through a cloud folder too, use the folder another device in this group already added. Your Wi-Fi pairings stay as they are.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Use this group's cloud folder…") { sheet = .picker }.disabled(coordinator.isBusy)
                Button(SyncWording.addFolderLabel) { startNewFolder(adding: true) }.disabled(coordinator.isBusy)
            } else {
                Text(DeviceText.isPad ? String(localized: "ipad.sync.cloudHelp", defaultValue: "To join, choose the folder your other device already uses (it holds LocalGateKeys Sync) and enter its sync password. To start syncing from this iPad, choose Start a new folder and pick an empty folder in your cloud app. If your cloud app is greyed out, it doesn't let other apps open its folders on iPad: sync over Wi-Fi or through iCloud Drive instead.")
                     : String(localized: "To join, choose the folder your other device already uses (it holds LocalGateKeys Sync) and enter its sync password. To start syncing from this iPhone, choose Start a new folder and pick an empty folder in your cloud app. If your cloud app is greyed out, it doesn't let other apps open its folders on iPhone: sync over Wi-Fi or through iCloud Drive instead."))
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Join a folder…") { sheet = .picker }.disabled(coordinator.isBusy)
                Button("Start a new folder…") { startNewFolder() }.disabled(coordinator.isBusy)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// The keyring members (this iPhone first), the unconfirmed ones marked, then Remove and I lost a device.
    @ViewBuilder private var folderMembers: some View {
        let m = coordinator.membership
        let names = DeviceRemoval.memberNames(coordinator.groupState())
        let unacked = Set(m.unacked)
        let others = m.members.filter { $0 != m.deviceID }
        if !m.members.isEmpty {
            Text("Devices").font(.footnote.weight(.semibold)).foregroundStyle(Palette.secondaryText)
            ForEach(m.members.filter { $0 == m.deviceID } + others, id: \.self) { id in
                VStack(alignment: .leading, spacing: 2) {
                    Text(names[id] ?? SyncWording.shortID(id)).foregroundStyle(Palette.text)
                    if id == m.deviceID {
                        Text(DeviceText.isPad ? String(localized: "ipad.sync.thisDeviceTitle", defaultValue: "This iPad") : String(localized: "This iPhone")).font(.footnote).foregroundStyle(Palette.secondaryText)
                    } else if unacked.contains(id) {
                        Text("Added by another device, not confirmed").font(.footnote).foregroundStyle(Palette.warning)
                    }
                }
            }
        }
        if others.contains(where: { unacked.contains($0) }) {
            Text("These devices were added to this sync group by another device. If they are yours, choose These are my devices. Devices you haven't confirmed lose access at the next sync key change.")
                .font(.footnote).foregroundStyle(Palette.warning).fixedSize(horizontal: false, vertical: true)
            Button("These are my devices") {
                let ids = others.filter { unacked.contains($0) }
                Task { await coordinator.acknowledgeMembers(ids) }
            }.disabled(coordinator.isBusy)
        }
        if !others.isEmpty && m.hasBookmark {
            Button(DeviceRemoval.removeLabel) { startRemoval(lost: false) }.disabled(coordinator.isBusy)
            Button(DeviceRemoval.lostLabel) { startRemoval(lost: true) }.disabled(coordinator.isBusy)
        }
    }

    /// The members this iPhone may remove (every keyring member but itself).
    private var candidates: [RemoveDevicesChooser.Candidate] {
        let m = coordinator.membership
        let names = DeviceRemoval.memberNames(coordinator.groupState())
        let unacked = Set(m.unacked)
        return m.members.filter { $0 != m.deviceID }.map { id in
            RemoveDevicesChooser.Candidate(id: id, name: names[id] ?? SyncWording.shortID(id),
                                           detail: unacked.contains(id) ? String(localized: "Added by another device, not confirmed") : "")
        }
    }

    /// Pro first (the upgrade sheet otherwise), then the chooser.
    /// Start a new folder: creating a sync group needs Pro, as on the Mac and PC (joining stays free).
    /// `adding`: give this device's Wi-Fi group the folder (also Pro) instead of starting a new group.
    private func startNewFolder(adding: Bool = false) {
        localError = nil
        addingFolder = adding
        guard pro?.isPro == true else {
            if pro != nil { showUpgrade = true }
            return
        }
        sheet = .createPicker
    }

    private func startRemoval(lost: Bool) {
        localError = nil
        guard pro?.isPro == true else {
            if pro != nil { showUpgrade = true }
            return
        }
        choosing = Choosing(lost: lost)
    }

    private func makePlan(_ ids: [String], lost: Bool) -> DeviceRemoval.Plan? {
        guard let state = coordinator.groupState() else { return nil }
        let m = coordinator.membership
        let names = DeviceRemoval.memberNames(state)
        let qr = m.wifiPeers.filter { !ids.contains($0) }.map { SyncWording.labeled(m.names[$0], $0) }
        return DeviceRemoval.plan(state, removing: ids, names: names, qrPeers: qr, lost: lost)
    }

    private var issuesSection: some View {
        Section("Messages") {
            ForEach(coordinator.issues) { issue in
                VStack(alignment: .leading, spacing: 6) {
                    if issue.kind == "vault-rollback" {
                        Text(SyncWording.rollbackTitle).font(.headline).foregroundStyle(color(issue.severity))
                    }
                    Label(issue.text, systemImage: icon(issue.severity))
                        .foregroundStyle(color(issue.severity))
                    if issue.kind == "vault-rollback" {
                        Button(SyncWording.rollbackAction) { confirm = .rollback }.disabled(coordinator.isBusy)
                    }
                    if issue.kind == "peer-vault-rollback", !issue.detail.isEmpty {
                        Button(SyncWording.peerRollbackDismiss) {
                            Task { await coordinator.dismissPeerRollback(issue.detail) }
                        }.disabled(coordinator.isBusy)
                    }
                    if issue.resetOffered {
                        Button(DeviceText.isPad ? String(localized: "ipad.syncScreen.resetSyncButton", defaultValue: "Reset sync on this iPad…") : String(localized: "Reset sync on this iPhone…")) { confirm = .reset1 }
                    }
                }
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var leaveSection: some View {
        Section {
            Button("Leave sync…", role: .destructive) { confirm = .leave1 }.disabled(coordinator.isBusy)
            Button(DeviceText.isPad ? String(localized: "ipad.syncScreen.resetSyncButton", defaultValue: "Reset sync on this iPad…") : String(localized: "Reset sync on this iPhone…"), role: .destructive) { confirm = .reset1 }.disabled(coordinator.isBusy)
        }
        .listRowBackground(Palette.groupSurface)
    }

    private func icon(_ s: SyncWording.Severity) -> String {
        switch s { case .error: "xmark.octagon"; case .warning: "exclamationmark.triangle"; case .notice: "info.circle" }
    }

    private func color(_ s: SyncWording.Severity) -> Color {
        switch s { case .error: Palette.danger; case .warning: Palette.warning; case .notice: Palette.secondaryText }
    }

    // MARK: confirmations (two for Leave, two for Reset)

    private var confirmTitle: String {
        switch confirm {
        case .leave1, .leave2: String(localized: "Leave sync")
        case .rollback: SyncWording.rollbackConfirmTitle
        case .freshKey: SyncWording.newKeyTitle
        case .removePeer: String(localized: "Remove") + "?"
        default: DeviceText.isPad ? String(localized: "ipad.syncScreen.resetSyncTitle", defaultValue: "Reset sync on this iPad") : String(localized: "Reset sync on this iPhone")
        }
    }

    private var confirmMessage: String {
        switch confirm {
        case .leave1: coordinator.membership.hasFolder ? SyncWording.leaveText : SyncWording.leaveWifiText
        case .leave2: SyncWording.leaveText2
        case .reset1: SyncWording.resetText1
        case .reset2: SyncWording.resetText2
        case .rollback: SyncWording.rollbackConfirmText
        case .freshKey:
            SyncWording.newKeyFolderText(peers: coordinator.membership.wifiPeers.map {
                SyncWording.labeled(coordinator.membership.names[$0], $0)
            })
        case .removePeer(_, let name): PhoneWiFiHost.removeDeviceText(name)
        case nil: ""
        }
    }

    @ViewBuilder private var confirmButtons: some View {
        switch confirm {
        case .leave1: Button("Continue", role: .destructive) { next(.leave2) }
        case .leave2: Button("Leave sync", role: .destructive) { confirm = nil; Task { await coordinator.leave() } }
        case .reset1: Button("Continue", role: .destructive) { next(.reset2) }
        case .reset2: Button("Reset", role: .destructive) { confirm = nil; Task { await coordinator.reset() } }
        case .freshKey:
            Button("Continue") {
                let pw = freshKeyPassword ?? "", bookmark = pickedBookmark ?? []
                confirm = nil; freshKeyPassword = nil
                Task { await coordinator.createFolder(bookmark: bookmark, password: pw, add: true, freshKey: true) }
            }
        case .rollback:
            Button("Keep this copy") {
                confirm = nil
                Task { await coordinator.acknowledgeRollback(reauthenticate: { await Self.confirmOwner() }) }
            }
        case .removePeer(let id, let name):
            Button("Remove", role: .destructive) { confirm = nil; wifiHost?.removePeer(id, name: name) }
        case nil: EmptyView()
        }
        Button("Cancel", role: .cancel) { confirm = nil; freshKeyPassword = nil }
    }

    /// Face ID / Touch ID or the device passcode, asked again for this step (no reuse of the unlock); with the app
    /// password on, `AppPasswordGate` (never the passcode).
    @MainActor static func confirmOwner() async -> Bool {
        // A fresh LAContext each time (no reuse of the unlock); says why when the check cannot run (review L3).
        await AppPasswordGate.confirmOwner(String(localized: "Confirm that you restored this vault"))
    }

    private func next(_ step: Confirm) {
        confirm = nil
        // Present the second alert after the first one has gone.
        DispatchQueue.main.async { confirm = step }
    }

    // MARK: sheets

    @ViewBuilder private func sheetView(_ which: Sheet) -> some View {
        switch which {
        case .scanner:
            NavigationStack {
                QRScanner(onCode: { code in sheet = nil; localError = nil; Task { await coordinator.joinByQR(code) } },
                          onUnavailable: { sheet = nil; localError = String(localized: "The camera is not available. Use Paste code text instead.") })
                    .ignoresSafeArea()
                    .navigationTitle("Scan QR code")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { sheet = nil } } }
            }
        case .findAgain:
            NavigationStack {
                QRScanner(onCode: { code in sheet = nil; localError = nil; Task { await coordinator.findAgain(code) } },
                          onUnavailable: { sheet = nil; localError = String(localized: "The camera is not available.") })
                    .ignoresSafeArea()
                    .navigationTitle(SyncWording.findAgainAction)
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { sheet = nil } } }
            }
        case .paste:
            NavigationStack {
                Form {
                    Section(footer: Text("On your PC choose Copy code text, then paste it here.")) {
                        TextField("lgk-pair:…", text: $pastedCode, axis: .vertical)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                .navigationTitle("Paste code text")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { sheet = nil } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Join") { let code = pastedCode; sheet = nil; localError = nil; Task { await coordinator.joinByQR(code) } }
                            .disabled(pastedCode.isEmpty)
                    }
                }
            }
        case .picker:
            FolderPicker(onPick: { url in
                do {
                    let bookmark = try coordinator.deps.folders.bookmark(for: url)
                    sheet = nil
                    if coordinator.membership.hasFolder {
                        // Choosing the folder again: no password, the folder must hold this group.
                        Task { await coordinator.joinFolder(bookmark: bookmark, password: "") }
                    } else {
                        pickedBookmark = bookmark; password = ""
                        DispatchQueue.main.async { sheet = .password }
                    }
                } catch {
                    sheet = nil
                    localError = SyncWording.errorText(reason: "folder-error")
                }
            }, onCancel: { sheet = nil })
        case .createPicker:
            FolderPicker(onPick: { url in
                do {
                    let bookmark = try coordinator.deps.folders.bookmark(for: url)
                    pickedBookmark = bookmark; password = ""; passwordAgain = ""
                    sheet = nil
                    DispatchQueue.main.async { sheet = .createPassword }
                } catch {
                    sheet = nil
                    localError = SyncWording.errorText(reason: "folder-error")
                }
            }, onCancel: { sheet = nil })
        case .createPassword:
            NavigationStack {
                Form {
                    Section(footer: Text("At least 12 characters with a Strong rating. Write this password down: your other devices join this folder with it. It is never stored.")) {
                        SecureField("New sync password", text: $password)
                            .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("Sync password again", text: $passwordAgain)
                            .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                .navigationTitle(addingFolder ? SyncWording.addFolderTitle : String(localized: "New sync folder"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { password = ""; passwordAgain = ""; sheet = nil }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Create") {
                            let pw = password, again = passwordAgain, bookmark = pickedBookmark ?? []
                            password = ""; passwordAgain = ""; sheet = nil
                            guard pw == again else { localError = DeviceRemoval.mismatchText; return }
                            localError = nil
                            guard addingFolder else {
                                Task { await coordinator.createFolder(bookmark: bookmark, password: pw, add: false) }
                                return
                            }
                            // A removed Wi-Fi device still knows the key: the folder gets a new one, after a confirmation.
                            if coordinator.groupState()?.lanPeers.contains(where: \.revoked) ?? false {
                                freshKeyPassword = pw
                                DispatchQueue.main.async { confirm = .freshKey }
                            } else {
                                Task { await coordinator.createFolder(bookmark: bookmark, password: pw, add: true) }
                            }
                        }
                        .disabled(password.isEmpty || passwordAgain.isEmpty || pickedBookmark == nil)
                    }
                }
            }
        case .password:
            NavigationStack {
                Form {
                    Section(footer: Text("The sync password of this folder's group. It is never stored.")) {
                        SecureField("Sync password", text: $password)
                            .textContentType(VaultInputTraits.secretContentType).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                .navigationTitle("Sync password")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { password = ""; sheet = nil } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Join") {
                            let pw = password, bookmark = pickedBookmark ?? []
                            password = ""; sheet = nil; localError = nil
                            Task { await coordinator.joinFolder(bookmark: bookmark, password: pw) }
                        }
                        .disabled(password.isEmpty || pickedBookmark == nil)
                    }
                }
            }
        }
    }
}
