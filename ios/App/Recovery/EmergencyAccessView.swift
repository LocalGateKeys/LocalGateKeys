import SwiftUI
import LocalAuthentication
import UniformTypeIdentifiers
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

extension EmergencyAccess {
    /// Emergency access over this unlocked vault, its heir folder opened from the stored security-scoped bookmark;
    /// a refusal written here is published by `onLocalEdit` (sync's `noteLocalEdit`). Nil when the store is not a
    /// `LocalStore` (previews, tests).
    static func live(store: any ItemStore, onLocalEdit: @escaping @MainActor () -> Void = {}) -> EmergencyAccess? {
        guard let local = HeirLocalState.open(for: store) else { return nil }
        let opener = SecurityScopedFolderOpener()
        return EmergencyAccess(store: store, local: local, openFolder: { bookmark in
            guard let opened = try? opener.open(bookmark: bookmark) else { return nil }
            return (HeirFolder(access: opened.folder), opened.refreshed)
        }, onLocalEdit: { Task { @MainActor in onLocalEdit() } })
    }

    @MainActor
    static func live(store: any ItemStore, sync: SyncCoordinator?) -> EmergencyAccess? {
        live(store: store, onLocalEdit: { [weak sync] in sync?.noteLocalEdit() })
    }
}

/// Asks the owner before an emergency access step that gives the vault away: granting now, showing a recovered phrase.
///
/// iPhone: Face ID, Touch ID or the device passcode (a device without a passcode has nothing to ask); with the app
/// password on, `AppPasswordGate` instead (never the passcode).
///
/// Mac (audit 2026-11-10): the master password, through `StrictItemGate` (master password only, no grace period). Never
/// the Mac's login password (`.deviceOwnerAuthentication`: anyone who knows it could give the vault away) and never
/// Touch ID: the Mac's Touch ID check (`MacLockModel.verifyWithTouchID`) only evaluates a policy; it releases no vault
/// key that could be compared with the open vault's. Without a gate (previews, tests) the step is refused.
enum OwnerCheck {
    #if os(iOS)
    @MainActor
    static func confirm(_ reason: String) async -> Bool {
        if let answer = await AppPasswordGate.confirm(reason) { return answer }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            if (error as? LAError)?.code == .passcodeNotSet { return true }
            // Face ID locked or another failure: say why instead of doing nothing (review L3).
            await AppPasswordGate.showProblem(AppPasswordGate.ownerCheckMessage(error) ?? AppPasswordGate.ownerCheckFailedText)
            return false
        }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            if let message = AppPasswordGate.ownerCheckMessage(error) { await AppPasswordGate.showProblem(message) }
            return false
        }
    }
    #else
    /// True once the master password is confirmed on `gate`'s prompt; false when cancelled, dropped by a lock, refused
    /// because another prompt is open, or without a gate.
    @MainActor
    static func confirm(_ reason: String, gate: StrictItemGate?) async -> Bool {
        guard let gate else { return false }
        return await gate.confirmMasterPassword(title: EmergencyAccessText.title, action: reason)
    }
    #endif
}

/// Settings › Emergency access (iPhone) and the Recovery centre's Emergency access card (Mac): sub-plan 08, Task 5c,
/// Android `EmergencyAccessScreen`. The owner's side (a synced plan: its folder, requests, deny and grant now) and the
/// holder's side (shards, ask for access, status, the owner's recovery phrase once access is open).
struct EmergencyAccessView: View {
    let access: EmergencyAccess
    #if os(macOS)
    /// The master password prompt before granting now and showing a recovered phrase (`OwnerCheck`); nil refuses both.
    var gate: StrictItemGate? = nil
    #endif
    /// The unlocked vault the estate pack note goes into (sub-plan 12); nil hides the Estate pack section.
    var estateStore: (any ItemStore)? = nil
    /// The free plan's item limit for the estate pack note.
    var isPro = false
    /// The free plan refused the estate pack note (the caller shows its upgrade sheet).
    var onNeedsPro: () -> Void = {}

    @State private var plan: HeirPlan?
    @State private var planDamaged = false
    @State private var hasFolder = false
    @State private var requests: [HeirRequest] = []
    @State private var shards: [Shard] = []
    @State private var status: HeirStatus?
    @State private var message: String?
    @State private var pasted = ""
    @State private var busy = false
    @State private var importing: ImportKind?
    @State private var granting: HeirRequest?
    @State private var phrase: String?

    private enum ImportKind { case folder, shard }

    var body: some View {
        Form {
            if let message {
                Section { Text(message).font(.footnote) }
            }
            ownerSection
            holderSection
            if estateStore != nil { estateSection }
        }
        .navigationTitle(EmergencyAccessText.title)
        .disabled(busy)
        .task { await reload() }
        .fileImporter(isPresented: Binding(get: { importing != nil }, set: { if !$0 { importing = nil } }),
                      allowedContentTypes: importing == .folder ? [.folder] : [.data, .item]) { result in
            let kind = importing
            importing = nil
            switch result {
            case .success(let url): picked(url, kind: kind)
            case .failure: message = kind == .folder ? EmergencyAccessText.noFolder : EmergencyAccessText.noFileChosen
            }
        }
        .sheet(item: $granting) { request in grantSheet(for: request) }
        .sheet(isPresented: Binding(get: { phrase != nil }, set: { if !$0 { phrase = nil } })) {
            PhraseSheet(phrase: phrase ?? "") { phrase = nil }
        }
        #if os(macOS)
        // The master password prompt for showing a phrase; while the grant sheet is open, that sheet shows it.
        .sheet(item: Binding(get: { granting == nil ? gate?.pending : nil }, set: { if $0 == nil { gate?.cancel() } })) { request in
            if let gate { StrictItemSheet(gate: gate, request: request).macThemed() }
        }
        #endif
    }

    private func grantSheet(for request: HeirRequest) -> GrantSheet {
        #if os(macOS)
        return GrantSheet(holder: request.holder, gate: gate) { typed in await grant(request, phrase: typed) }
        #else
        return GrantSheet(holder: request.holder) { typed in await grant(request, phrase: typed) }
        #endif
    }

    private func confirmOwner(_ reason: String) async -> Bool {
        #if os(macOS)
        return await OwnerCheck.confirm(reason, gate: gate)
        #else
        return await OwnerCheck.confirm(reason)
        #endif
    }

    // MARK: sections

    @ViewBuilder private var ownerSection: some View {
        Section {
            if let plan {
                Text(EmergencyAccessText.planLine(k: plan.k, n: plan.n, days: plan.waitDays, made: Self.date(plan.created)))
                Text(EmergencyAccessText.notHome).font(.footnote).foregroundStyle(.secondary)
                Text(EmergencyAccessText.collusion).font(.footnote).foregroundStyle(.secondary)
                folderRow
                if requests.isEmpty {
                    Text(EmergencyAccessText.noRequests).foregroundStyle(.secondary)
                }
                ForEach(requests) { r in
                    VStack(alignment: .leading, spacing: 6) {
                        if r.granted {
                            Text(r.holder)
                            Text(EmergencyAccessText.grantedLine).font(.footnote).foregroundStyle(.secondary)
                        } else {
                            Text(EmergencyAccessText.requestLine(holder: r.holder, date: Self.date(r.created), daysLeft: r.daysLeft))
                            HStack {
                                Button(EmergencyAccessText.deny, role: .destructive) { deny(r) }
                                Spacer()
                                Button(EmergencyAccessText.grant) { granting = r }
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
            } else {
                Text(planDamaged ? EmergencyAccessText.message(HeirError("malformed")) : EmergencyAccessText.noPlan)
                    .font(.footnote).foregroundStyle(.secondary)
            }
        } header: {
            Text(EmergencyAccessText.planSection)
        } footer: {
            Text(EmergencyAccessText.footer)
        }
    }

    /// Estate pack (sub-plan 12): a note with one heading per field, the shard holders listed by nickname.
    private var estateSection: some View {
        Section {
            Text(EstatePack.help).font(.footnote).foregroundStyle(.secondary)
            Button(EstatePack.createLabel) { createEstatePack() }
        } header: {
            Text(EstatePack.title)
        }
    }

    private func createEstatePack() {
        guard let estateStore else { return }
        switch EstatePack.create(in: estateStore, holders: plan?.holders ?? [], isPro: isPro) {
        case .created: message = EstatePack.created
        case .needsPro:
            message = String(localized: "The free plan holds \(ItemLimit.freeItems) items. Upgrade to Pro to add more.")
            onNeedsPro()
        case .failed: message = EstatePack.failed
        }
    }

    @ViewBuilder private var holderSection: some View {
        Section {
            Text(EmergencyAccessText.receiveMeta).font(.footnote).foregroundStyle(.secondary)
            if shards.isEmpty {
                Text(EmergencyAccessText.noShards).foregroundStyle(.secondary)
            } else {
                if let first = shards.first {
                    Text(EmergencyAccessText.planOf(owner: first.owner, k: first.k))
                }
                ForEach(shards, id: \.packageID) { s in
                    Text(EmergencyAccessText.shardLine(index: s.index, holder: s.holder))
                }
            }
            Button(EmergencyAccessText.addFile) { importing = .shard }
            HStack {
                TextField(EmergencyAccessText.paste, text: $pasted)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                Button(EmergencyAccessText.addText) { addPasted() }
                    .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            if plan == nil { folderRow }
            if !shards.isEmpty {
                if let status { Text(EmergencyAccessText.state(status)) }
                Button(EmergencyAccessText.request) { request() }
                Button(EmergencyAccessText.refresh) { Task { await reload() } }
                if status?.state == "ready" {
                    Button(EmergencyAccessText.showPhrase) { Task { await showPhrase() } }
                }
                Button(EmergencyAccessText.clear, role: .destructive) { clearShards() }
            }
        } header: {
            Text(EmergencyAccessText.receive)
        }
    }

    private var folderRow: some View {
        HStack {
            Text(EmergencyAccessText.folder)
            Spacer()
            if !hasFolder { Text(EmergencyAccessText.noFolder).foregroundStyle(.secondary) }
            Button(EmergencyAccessText.chooseFolder) { importing = .folder }.buttonStyle(.borderless)
        }
    }

    // MARK: actions (the heir code blocks: off the main actor)

    private func reload() async {
        let access = access
        let read = await Task.detached(priority: .userInitiated) { () -> Snapshot in
            var s = Snapshot()
            do { s.plan = try access.plan() } catch { s.damaged = true }
            s.hasFolder = access.hasFolder
            if s.plan != nil, s.hasFolder { s.requests = (try? access.pending().requests) ?? [] }
            s.shards = access.shards()
            if !s.shards.isEmpty, s.hasFolder { s.status = try? access.status() }
            return s
        }.value
        plan = read.plan; planDamaged = read.damaged; hasFolder = read.hasFolder
        requests = read.requests; shards = read.shards; status = read.status
    }

    private struct Snapshot: Sendable {
        var plan: HeirPlan?
        var damaged = false
        var hasFolder = false
        var requests: [HeirRequest] = []
        var shards: [Shard] = []
        var status: HeirStatus?
    }

    /// Runs `work` off the main actor; its result (or refusal) becomes the message, then everything is read again.
    private func run(_ work: @escaping @Sendable () throws -> String?) {
        busy = true
        Task {
            let result = await Task.detached(priority: .userInitiated) { () -> String? in
                do { return try work() } catch { return EmergencyAccessText.message(error) }
            }.value
            if let result { message = result }
            await reload()
            busy = false
        }
    }

    private func deny(_ r: HeirRequest) {
        let access = access
        run {
            try access.deny(requestID: r.requestID)
            return EmergencyAccessText.deniedMessage(r.holder)
        }
    }

    private func request() {
        guard hasFolder else { message = EmergencyAccessText.addShardFirst; return }
        let access = access, days = shards.first?.waitDays ?? 0
        run {
            try access.request()
            return EmergencyAccessText.requestSent(days: days)
        }
    }

    private func clearShards() {
        let access = access
        run { try access.clearShards(); return nil }
    }

    private func addPasted() {
        let text = pasted
        pasted = ""
        let access = access
        run { EmergencyAccessText.shardAdded(try access.addText(text).owner) }
    }

    private func picked(_ url: URL, kind: ImportKind?) {
        let access = access
        switch kind {
        case .folder:
            do {
                try access.setFolder(bookmark: try SecurityScopedFolderOpener().bookmark(for: url))
                message = EmergencyAccessText.folderSet
            } catch {
                message = EmergencyAccessText.message(HeirFlowError("no-folder"))
            }
            Task { await reload() }
        case .shard:
            let scoped = url.startAccessingSecurityScopedResource()
            let data = try? Data(contentsOf: url)
            if scoped { url.stopAccessingSecurityScopedResource() }
            guard let data else { message = EmergencyAccessText.noFileChosen; return }
            let bytes = Array(data)
            run { EmergencyAccessText.shardAdded(try access.addPackage(bytes).owner) }
        case nil:
            break
        }
    }

    private func grant(_ r: HeirRequest, phrase typed: String) async -> String? {
        guard await confirmOwner(EmergencyAccessText.grantTitle) else { return EmergencyAccessText.grantTitle }
        let access = access
        let outcome = await Task.detached(priority: .userInitiated) { () -> String? in
            do { _ = try access.grant(requestID: r.requestID, phrase: typed); return nil } catch {
                return EmergencyAccessText.message(error)
            }
        }.value
        if outcome == nil {
            message = EmergencyAccessText.grantedMessage(r.holder)
            await reload()
        }
        return outcome
    }

    private func showPhrase() async {
        guard await confirmOwner(EmergencyAccessText.showPhrase) else { return }
        busy = true
        let access = access
        let outcome = await Task.detached(priority: .userInitiated) { () -> Result<String, Error> in
            Result { try access.recoverPhrase() }
        }.value
        busy = false
        switch outcome {
        case .success(let p): phrase = p
        case .failure(let e): message = EmergencyAccessText.message(e)
        }
    }

    static func date(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .omitted)
    }
}

/// Grant now: the warning and the owner's recovery phrase. `submit` returns the problem, nil when granted.
private struct GrantSheet: View {
    let holder: String
    #if os(macOS)
    /// The master password prompt `submit` waits on (`OwnerCheck`), shown over this sheet.
    var gate: StrictItemGate? = nil
    #endif
    let submit: (String) async -> String?
    @State private var phrase = ""
    @State private var problem: String?
    @State private var busy = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(EmergencyAccessText.grantConfirm(holder))
                    SecureField(EmergencyAccessText.grantPhrase, text: $phrase)
                        .autocorrectionDisabled()
                } footer: {
                    if let problem { Text(problem) }
                }
                Button(EmergencyAccessText.grant) {
                    let typed = phrase
                    busy = true; problem = nil
                    Task {
                        let result = await submit(typed)
                        busy = false
                        if let result { problem = result } else { phrase = ""; dismiss() }
                    }
                }
                .disabled(busy || phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .navigationTitle(EmergencyAccessText.grantTitle)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { phrase = ""; dismiss() }.disabled(busy) } }
        }
        #if os(macOS)
        .sheet(item: Binding(get: { gate?.pending }, set: { if $0 == nil { gate?.cancel() } })) { request in
            if let gate { StrictItemSheet(gate: gate, request: request).macThemed() }
        }
        #endif
    }
}

/// The owner's recovered phrase, shown once; nothing of it is kept when the sheet closes.
private struct PhraseSheet: View {
    let phrase: String
    let done: () -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(phrase).font(.system(.body, design: .monospaced)).textSelection(.disabled)
                } footer: {
                    Text(EmergencyAccessText.stateReady)
                }
            }
            .navigationTitle(EmergencyAccessText.phraseTitle)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { done() } } }
        }
    }
}

#if os(iOS)
/// The Settings row to the Emergency access screen. It shows in every session, as on Android and the desktop (review
/// M6): inside a duress session it opens over the second vault's own store and folder (no plan, no shards) and never
/// touches sync.
struct EmergencyAccessRow: View {
    let lock: AppLockModel
    let sync: SyncCoordinator
    var isPro = false
    var onNeedsPro: () -> Void = {}

    var body: some View {
        if let store = lock.store, let access = EmergencyAccess.live(store: store, sync: lock.secondSession ? nil : sync) {
            Section {
                NavigationLink(EmergencyAccessText.title) {
                    EmergencyAccessView(access: access, estateStore: store, isPro: isPro, onNeedsPro: onNeedsPro)
                }
            } footer: {
                Text(EmergencyAccessText.footer)
            }
            .listRowBackground(Palette.groupSurface)
        }
    }
}
#endif
