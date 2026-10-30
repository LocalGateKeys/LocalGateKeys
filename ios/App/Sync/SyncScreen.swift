import SwiftUI
import LocalAuthentication
import AppShared

/// Sync: Wi-Fi card (pair by QR), Cloud folder card (join or attach), status, issues with the desktop's
/// wording, Leave and Reset (two confirmations each).
struct SyncScreen: View {
    let coordinator: SyncCoordinator
    /// False when shown as the Sync tab (no Done button).
    var showsDone = true
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    private enum Sheet: String, Identifiable { case scanner, paste, picker, password, findAgain; var id: String { rawValue } }
    private enum Confirm: Equatable { case leave1, leave2, reset1, reset2, rollback }

    @State private var sheet: Sheet?
    @State private var confirm: Confirm?
    @State private var pastedCode = ""
    @State private var pickedBookmark: [UInt8]?
    @State private var password = ""
    @State private var localError: String?

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
                .refreshable { await coordinator.sync(.pullToRefresh) }
                .onAppear { coordinator.refreshMembership() }
                .sheet(item: $sheet) { which in sheetView(which) }
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
                Button("Sync now") { Task { await coordinator.sync(.manual) } }.disabled(coordinator.isBusy)
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
            guard coordinator.membership.joined else { return String(localized: "Sync is not set up on this iPhone.") }
            guard let at = coordinator.lastSyncedAt else { return String(localized: "Not synced since you unlocked.") }
            return String(localized: "Last synced \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .omitted, time: .shortened)).")
        }
    }

    private var wifiSection: some View {
        Section("Wi-Fi") {
            if let peer = coordinator.membership.peer {
                Text("Paired with \(SyncWording.shortID(peer.deviceID))").foregroundStyle(Palette.text)
                if let ep = peer.endpoint { Text("\(ep.host) port \(ep.port)").font(.footnote).foregroundStyle(Palette.secondaryText) }
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
            } else {
                Text("This iPhone syncs through the cloud folder only.").font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var folderSection: some View {
        Section("Cloud folder") {
            let m = coordinator.membership
            if m.hasFolder {
                Text(m.hasBookmark ? String(localized: "Syncing through the cloud folder.") : String(localized: "Choose the sync folder again on this iPhone."))
                    .foregroundStyle(m.hasBookmark ? Palette.text : Palette.warning)
                Button("Choose the folder again…") { sheet = .picker }.disabled(coordinator.isBusy)
            } else if m.joined {
                Text("To sync through a cloud folder too, use the folder another device in this group already added. Your Wi-Fi pairings stay as they are.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Use this group's cloud folder…") { sheet = .picker }.disabled(coordinator.isBusy)
            } else {
                Text("Choose the folder your cloud app syncs, the one that holds LocalGateKeys Sync, and enter the sync password. If your cloud app is greyed out, it doesn't let other apps open its folders on iPhone: sync over Wi-Fi or through iCloud Drive instead.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Join a folder…") { sheet = .picker }.disabled(coordinator.isBusy)
            }
        }
        .listRowBackground(Palette.groupSurface)
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
                        Button("Reset sync on this iPhone…") { confirm = .reset1 }
                    }
                }
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var leaveSection: some View {
        Section {
            Button("Leave sync…", role: .destructive) { confirm = .leave1 }.disabled(coordinator.isBusy)
            Button("Reset sync on this iPhone…", role: .destructive) { confirm = .reset1 }.disabled(coordinator.isBusy)
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
        default: String(localized: "Reset sync on this iPhone")
        }
    }

    private var confirmMessage: String {
        switch confirm {
        case .leave1: coordinator.membership.hasFolder ? SyncWording.leaveText : SyncWording.leaveWifiText
        case .leave2: SyncWording.leaveText2
        case .reset1: SyncWording.resetText1
        case .reset2: SyncWording.resetText2
        case .rollback: SyncWording.rollbackConfirmText
        case nil: ""
        }
    }

    @ViewBuilder private var confirmButtons: some View {
        switch confirm {
        case .leave1: Button("Continue", role: .destructive) { next(.leave2) }
        case .leave2: Button("Leave sync", role: .destructive) { confirm = nil; Task { await coordinator.leave() } }
        case .reset1: Button("Continue", role: .destructive) { next(.reset2) }
        case .reset2: Button("Reset", role: .destructive) { confirm = nil; Task { await coordinator.reset() } }
        case .rollback:
            Button("Keep this copy") {
                confirm = nil
                Task { await coordinator.acknowledgeRollback(reauthenticate: { await Self.confirmOwner() }) }
            }
        case nil: EmptyView()
        }
        Button("Cancel", role: .cancel) { confirm = nil }
    }

    /// Face ID / Touch ID or the device passcode, asked again for this step (no reuse of the unlock).
    @MainActor static func confirmOwner() async -> Bool {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication,
                                              localizedReason: String(localized: "Confirm that you restored this vault"))) ?? false
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
