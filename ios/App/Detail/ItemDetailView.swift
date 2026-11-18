import SwiftUI
import Combine
import AppShared

struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    private let store: any ItemStore
    private let pro: ProModel
    private let onChange: () -> Void
    @State private var editing = false
    @State private var editingPasskey = false
    @State private var confirmDelete = false
    @State private var deleteResult: SaveResult?
    /// The star's state: the item's `favorite`, then what the last toggle wrote.
    @State private var favorite: Bool
    @State private var favoriteFailed = false
    /// Share (UX workstream 9): the sheet with the six-word code, the file and the QR.
    @State private var sharing = false
    /// The live 2FA code of a login whose rules mask its secrets was shown after the owner check (feature pack §4).
    @State private var codeShown = false
    /// The Wi-Fi QR sheet (after the password is revealed).
    @State private var showingWifiQR = false
    /// "Set expiry from token" could not be saved.
    @State private var expiryFailed = false
    /// The expiry was written; this screen keeps its model, so the button is hidden.
    @State private var expirySet = false
    /// The item's collections by name (sub-plan 07), read once when the screen opens (not on every tick).
    @State private var collectionNames: [String] = []
    /// In a collection shared with this vault as view only: no Edit, Delete or star.
    @State private var readOnly = false
    /// The per-device "Show formatting" switch under a note (Markdown, default on).
    @AppStorage(NoteFormatting.settingKey) private var showFormatting = true
    @Environment(\.dismiss) private var dismiss
    @Environment(\.phoneTrash) private var trash
    @Environment(\.phoneReminders) private var reminders

    init(item: VaultItem, store: any ItemStore, pro: ProModel, onChange: @escaping () -> Void) {
        _model = State(initialValue: ItemDetailModel(item: item, clipboard: SecretClipboard.shared, clock: SystemClock(),
                                                         concealSecrets: AccessGate.shared.concealsOnOpen(
                                                            item, setting: AppSettings.shared.concealSecretsInDetail)))
        _favorite = State(initialValue: item.favorite)
        self.store = store; self.pro = pro; self.onChange = onChange
    }

    @Environment(\.openURL) private var openURL
    /// Feature pack §6.3: the site of this login supports passkeys and none is saved for it (nil: no prompt).
    @State private var passkeyDomain: String?

    @ViewBuilder private var passkeyUpgradeCard: some View {
        if let passkeyDomain, !readOnly {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label(String(localized: "\(passkeyDomain) supports passkeys"), systemImage: "person.badge.key")
                        .font(.headline).foregroundStyle(Palette.text)
                    Text("A passkey can't be phished or leaked. Add one in the site's security settings; LocalGateKeys saves it when you choose it as the passkey provider.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                    HStack {
                        if let url = model.item.openableURL {
                            Button("Open website") { openURL(url) }.buttonStyle(.borderless).foregroundStyle(Palette.accentText)
                        }
                        Spacer()
                        Button("Not now") { dismissPasskeyUpgrade(passkeyDomain) }.buttonStyle(.borderless)
                            .foregroundStyle(Palette.secondaryText)
                    }
                }
                .accessibilityElement(children: .contain)
            }
            .listRowBackground(Palette.groupSurface)
        }
    }

    private func loadPasskeyUpgrade() async {
        guard model.item.kind == "web", let snap = try? store.load() else { passkeyDomain = nil; return }
        let record = model.item.record
        let rpIDs: [String] = snap.itemRecords.compactMap { id, wrapper in
            guard snap.meta[id]?.deleted != true, case .object(let w) = wrapper, case .object(let r)? = w["record"],
                  r["kind"] == .string("passkey"), case .string(let rp)? = r["payload"]?.objectValue?["relying_party_id"] else { return nil }
            return rp
        }
        let domain = await Task.detached(priority: .utility) { () -> String? in
            let features = SiteFeatures.bundled()
            return PasskeyUpgrade.domain(for: record, features: features,
                                         passkeyDomains: features.passkeyDomains(relyingPartyIDs: rpIDs))
        }.value
        let dismissed = HistoryRecorder.shared.host?.localData?.passkeyUpgradeDismissed ?? [:]
        passkeyDomain = domain.flatMap { PasskeyUpgrade.isDismissed($0, in: dismissed, now: SystemClock().now) ? nil : $0 }
    }

    private func dismissPasskeyUpgrade(_ domain: String) {
        passkeyDomain = nil
        guard let local = HistoryRecorder.shared.host, var data = local.localData else { return }
        data.passkeyUpgradeDismissed = PasskeyUpgrade.dismissing(domain, in: data.passkeyUpgradeDismissed, now: SystemClock().now)
        try? local.commitLocalData(data)
    }
    /// The pin message after a tap (limit or Pro).
    @State private var watchMessage: String?

    /// Pins or unpins this item's 2FA code for the iPhone widgets, the Shortcuts action and, when paired, the
    /// Apple Watch app. Shown for every item with a code, with or without a watch.
    @ViewBuilder private var watchPinRow: some View {
        let watch = WatchCodes.shared
        let pinned = watch.isPinned(model.item.id)
        Button {
            guard let snapshot = try? store.load() else { return }
            switch watch.toggle(model.item.id, snapshot: snapshot, isPro: pro.isPro) {
            case .pinned:
                watchMessage = nil
                CopyToast.shared.show(watch.watchAvailable ? String(localized: "Sent to Apple Watch") : String(localized: "Pinned for widgets"))
            case .unpinned:
                watchMessage = nil
                CopyToast.shared.show(watch.watchAvailable ? String(localized: "Removed from Apple Watch") : String(localized: "Removed from widgets"))
            case .limitReached:
                watchMessage = String(localized: "Up to \(WatchMessage.maxPins) codes can be pinned. Widgets and Shortcuts use the first \(PinnedCodeStore.maxShown); Apple Watch shows all. Remove one first.")
            case .needsPro: watchMessage = String(localized: "Apple Watch codes are part of Pro, like all 2FA.")
            }
        } label: {
            Label(pinned ? String(localized: "Remove from widgets and Apple Watch") : String(localized: "Show in widgets and on Apple Watch"),
                  systemImage: pinned ? "pin.slash" : "pin")
        }
        .foregroundStyle(Palette.accentText)
        if let watchMessage {
            Text(watchMessage).font(.footnote).foregroundStyle(Palette.secondaryText)
        }
    }

    /// Feature pack §4: the login's access rules on this phone, shown above its fields.
    @ViewBuilder private var accessBanner: some View {
        let rules = PhoneFeaturePack.rules(model.item)
        if rules.unknownRule || rules.expired || rules.anyRule {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    if rules.unknownRule {
                        Label("This login has a rule from a newer version, so the strictest rules apply here.", systemImage: "lock.shield")
                    } else if rules.expired {
                        Label(rules.expiresOn.map { String(localized: "Access expired on \($0). Confirming it's you is needed for every use.") }
                              ?? String(localized: "Access has expired. Confirming it's you is needed for every use."),
                              systemImage: "clock.badge.exclamationmark")
                    } else {
                        Label("This login has access rules.", systemImage: "lock.shield")
                    }
                    if rules.phoneView { Text("View only on phones.").font(.footnote) }
                    if rules.copyOnce { Text("Copy once per unlock, then confirm again.").font(.footnote) }
                    if rules.reauth && !rules.expired { Text("Asks to confirm it's you for every reveal, copy and fill.").font(.footnote) }
                    if !rules.autofill { Text("Not offered by AutoFill on this phone.").font(.footnote) }
                }
                .foregroundStyle(Palette.text)
                .accessibilityElement(children: .combine)
            }
            .listRowBackground(Palette.groupSurface)
        }
    }

    var body: some View {
        List {
            Section { header }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            accessBanner
            passkeyUpgradeCard
            if let totp = model.totp {
                // Feature pack §4: on a login whose rules mask its secrets, the live code is masked too until the
                // owner confirms (final review S-M2; the Mac's DetailPanel does the same).
                let codeMasked = !codeShown && AccessGate.shared.masksSecrets(model.item)
                Section("One-time code") {
                    HStack(spacing: 16) {
                        TOTPRing(fraction: totp.fractionRemaining, seconds: totp.secondsRemaining)
                        Text(codeMasked ? ItemDetailModel.mask : totp.code)
                            .font(.system(.title, design: .monospaced)).foregroundStyle(Palette.text)
                        Spacer()
                        if codeMasked {
                            Button {
                                Task { if await AccessGate.shared.mayReveal(model.item) { codeShown = true } }
                            } label: { Image(systemName: "eye") }
                                .buttonStyle(.borderless)
                                .disabled(model.screenCaptured)
                                .accessibilityLabel(String(localized: "Reveal"))
                        }
                        Button {
                            Task {
                                guard await AccessGate.shared.mayCopy(model.item) else { return }
                                if model.copyTOTP(clearAfterAtMost: AccessGate.shared.copyLimit(model.item)) {
                                    CopyToast.shared.show(String(localized: "Code copied"))
                                }
                            }
                        } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless).accessibilityLabel("Copy code")
                    }
                    watchPinRow
                }
                .listRowBackground(Palette.groupSurface)
            }
            Section {
                ForEach(model.fields) { field in
                    let isNote = NoteFormatting.formats(kind: model.item.kind, fieldId: field.id)
                    // Formatting applies to revealed text only.
                    let formatted = isNote && showFormatting && (!field.isSecret || model.isRevealed(field))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.label).font(.caption).foregroundStyle(Palette.secondaryText)
                        HStack(alignment: .firstTextBaseline) {
                            if formatted {
                                MarkdownNoteView(text: field.value, colors: Self.noteColors, selectable: false)
                            } else {
                                Text(model.displayValue(field))
                                    .font(field.isSecret ? .system(.body, design: .monospaced) : .body)
                                    .foregroundStyle(Palette.text).textSelection(.disabled)
                            }
                            Spacer()
                            if field.isSecret {
                                Button {
                                    if model.isRevealed(field) { model.toggleReveal(field) } else {
                                        Task { if await AccessGate.shared.mayReveal(model.item) { model.toggleReveal(field) } }
                                    }
                                } label: {
                                    Image(systemName: model.isRevealed(field) ? "eye.slash" : "eye")
                                }
                                .buttonStyle(.borderless)
                                .disabled(model.screenCaptured)
                                .accessibilityLabel(model.isRevealed(field) ? String(localized: "Hide") : String(localized: "Reveal"))
                            }
                            Button {
                                Task {
                                    guard await AccessGate.shared.mayCopy(model.item, secret: field.isSecret) else { return }
                                    model.copy(field, clearAfterAtMost: field.isSecret ? AccessGate.shared.copyLimit(model.item) : nil)
                                    CopyToast.shared.show(String(localized: "\(field.label) copied"))
                                }
                            } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).accessibilityLabel("Copy \(field.label)")
                        }
                        if field.id == "password" {
                            StrengthMeter(level: GeneratorStrength.estimate(password: field.value)).padding(.top, 2)
                        }
                        if isNote { ShowFormattingToggle(isOn: $showFormatting).tint(Palette.accent) }
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
            ForEach(model.fields) { field in
                if let info = model.token(for: field) { tokenSection(info, field: field) }
            }
            if model.item.kind == "wifi" { wifiQRSection }
            if model.item.kind == AttachmentDocuments.kind {
                DocumentSection(item: model.item, store: store, onChange: onChange)
            }
            if model.item.kind == "web" {
                let count = PasswordHistory.entries(model.item.record).count
                Section {
                    NavigationLink {
                        PasswordHistoryView(item: model.item, store: store, onChange: itemChanged)
                    } label: {
                        LabeledContent("Password history", value: count == 0 ? String(localized: "None") : "\(count)")
                    }
                    .disabled(count == 0)
                }
                .listRowBackground(Palette.groupSurface)
            }
            // Feature pack §4: a login's access rules (Pro to set or tighten).
            if model.item.kind == "web" && !readOnly {
                Section {
                    NavigationLink {
                        AccessRulesView(item: model.item, store: store, pro: pro, onChange: itemChanged)
                    } label: {
                        LabeledContent("Access rules",
                                       value: PhoneFeaturePack.rules(model.item).anyRule ? String(localized: "On") : String(localized: "None"))
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
            // Feature pack §1: earlier versions kept on this device.
            if let history = HistoryRecorder.shared.host?.localData?.itemHistory {
                let versions = ItemHistory.versions(of: model.item.id, in: history).count
                Section {
                    NavigationLink {
                        ItemHistoryView(item: model.item, store: store, pro: pro, readOnly: readOnly, onChange: itemChanged)
                    } label: {
                        LabeledContent("Item history", value: versions == 0 ? String(localized: "None") : "\(versions)")
                    }
                    .disabled(versions == 0)
                }
                .listRowBackground(Palette.groupSurface)
            }
            if !collectionNames.isEmpty || readOnly { collectionsSection }
            if let reminders { ItemReminderSection(reminders: reminders, item: model.item) }
            if let copied = model.lastCopied {
                Text("\(copied) copied. It clears from the clipboard in \(AppSettings.shared.clipboardExpiry.label).")
                    .font(.footnote).foregroundStyle(Palette.secondaryText).listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle(model.item.title.isEmpty ? model.item.kindLabel : model.item.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: toggleFavorite) {
                    Image(systemName: favorite ? "star.fill" : "star").foregroundStyle(favorite ? Palette.warning : Palette.accentText)
                }
                .accessibilityLabel(favorite ? String(localized: "Remove from favorites") : String(localized: "Add to favorites"))
                .disabled(readOnly)
            }
            if Share.canShare(model.item.record), AccessGate.shared.mayShare(model.item) {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { sharing = true } label: { Image(systemName: "square.and.arrow.up") }
                        .accessibilityLabel("Share")
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                // Other kinds are read-only on the phone and kept intact; so is any item in a view-only shared
                // collection (the Collections section says why).
                if readOnly { EmptyView() }
                else if EditorKind(kind: model.item.kind) != nil { Button("Edit") { editing = true } }
                else if model.item.kind == "passkey" { Button("Edit") { editingPasskey = true } }
                else if ItemDetailModel.offersDeleteOnly(kind: model.item.kind) {
                    Button("Delete", role: .destructive) { confirmDelete = true }
                }
            }
        }
        // An alert with a visible Cancel, as in the editor (tester feedback 1).
        .alert("Delete this item?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { deleteNow() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(model.item.kind == AttachmentDocuments.kind
                 ? (DeviceText.isPad ? String(localized: "ipad.itemDetailView.itemAndItsFile", defaultValue: "The item and its file are removed from this iPad and from your other devices at the next sync.") : String(localized: "The item and its file are removed from this iPhone and from your other devices at the next sync."))
                 : (DeviceText.isPad ? String(localized: "ipad.itemDetailView.removedFromAndFrom", defaultValue: "It is removed from this iPad and from your other devices at the next sync. It can only be edited on your PC.") : String(localized: "It is removed from this iPhone and from your other devices at the next sync. It can only be edited on your PC.")))
        }
        .alert(deleteAlertTitle, isPresented: Binding(get: { deleteResult == .unchanged || deleteResult == .failed },
                                                      set: { if !$0 { deleteResult = nil } })) {
            Button("OK") {
                if deleteResult == .unchanged { onChange(); dismiss() }
                deleteResult = nil
            }
        }
        .alert("The favorite could not be saved on this device.", isPresented: $favoriteFailed) { Button("OK") {} }
        .alert("Couldn't set the expiry.", isPresented: $expiryFailed) { Button("OK") {} }
        .sheet(isPresented: $sharing) { ShareItemSheet(item: storedItem) }
        .sheet(isPresented: $showingWifiQR) { if let text = model.wifiQRText { WifiQRSheet(text: text) } }
        // A screen capture drops the reveal, and the QR with it.
        .onChange(of: model.wifiQRText) { _, text in if text == nil { showingWifiQR = false } }
        .sheet(isPresented: $editingPasskey) {
            PasskeyEditView(model: PasskeyRenameModel(store: store, item: storedItem, clock: SystemClock())) { result in
                if result == .saved { onChange(); dismiss() }
            }
        }
        .onReceive(ticker) { _ in model.tick() }
        .task(id: model.item.id) { loadCollections(); await loadPasskeyUpgrade() }
        .onChange(of: ScreenCaptureMonitor.shared.isCaptured, initial: true) { _, captured in
            model.screenCaptured = captured
            if captured { codeShown = false }
        }
        #if DEBUG
        .onAppear { if ScreenshotScreen.requested == .edit { editing = true } }
        #endif
        .sheet(isPresented: $editing) {
            // Editing and deleting are never limited, even over the free plan's item count.
            // The stored record, so a favorite toggled on this screen is not undone by the edit.
            let current = storedItem
            EditorView(model: EditorModel(store: store, pro: pro, editing: current,
                                          kind: EditorKind(kind: current.kind) ?? .note,
                                          clock: SystemClock(), random: SystemRandomSource(),
                                          keepsPasswordHistory: true),
                       pro: pro) { result in
                if result == .saved { onChange(); dismiss() }
            }
        }
    }
}

extension ItemDetailView {
    private static var noteColors: MarkdownNoteColors {
        MarkdownNoteColors(text: Palette.text, secondary: Palette.secondaryText, accent: Palette.accentText,
                           codeBackground: Palette.separator)
    }

    /// The decoded token of a revealed API-key value: read-only, signature not checked. "Set expiry from token" writes
    /// the `exp` date as the item's expiry (reminders read it).
    @ViewBuilder private func tokenSection(_ info: JWTInfo, field: DetailField) -> some View {
        let both = model.fields.filter { model.token(for: $0) != nil }.count > 1
        Section(both ? "\(String(localized: "Token")) · \(field.label)" : String(localized: "Token")) {
            ForEach(model.tokenRows(info)) { row in
                VStack(alignment: .leading, spacing: 4) {
                    Text(row.label).font(.caption).foregroundStyle(Palette.secondaryText)
                    HStack {
                        Text(row.value).foregroundStyle(Palette.text)
                        if row.expired { Text("Expired").font(.caption.bold()).foregroundStyle(Palette.danger) }
                    }
                }
            }
            Text("Signature not checked").font(.footnote).foregroundStyle(Palette.secondaryText)
            if !expirySet, !readOnly, model.canSetExpiry(from: info), let date = ItemDetailModel.expiryDate(info) {
                Button("Set expiry from token") { setExpiry(date) }.foregroundStyle(Palette.accentText)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private func setExpiry(_ date: String) {
        switch ItemDetailModel.setExpiry(date, item: storedItem, store: store, pro: pro) {
        case .saved: CopyToast.shared.show(String(localized: "Expiry set to \(date)."))
            expirySet = true; onChange()
        case .unchanged: break
        default: expiryFailed = true
        }
    }

    /// Show QR for a Wi-Fi network: revealing the password is the permission; enterprise types have no QR.
    @ViewBuilder private var wifiQRSection: some View {
        Section {
            if model.offersWifiQR {
                Button {
                    if let pw = model.wifiPasswordField, !model.isRevealed(pw) { model.toggleReveal(pw) }
                    showingWifiQR = model.wifiQRText != nil
                } label: { Label("Show QR", systemImage: "qrcode") }
                    .foregroundStyle(Palette.accentText)
                    .disabled(model.screenCaptured)
            } else {
                Text("Enterprise networks can't be shared with a QR code.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Big icon, name, what it is for, and Open website for logins and bookmarks.
    private var header: some View {
        VStack(spacing: 10) {
            ItemAvatar(item: model.item, size: 72)
            Text(model.item.title.isEmpty ? model.item.kindLabel : model.item.title)
                .font(.title2.bold()).foregroundStyle(Palette.text).multilineTextAlignment(.center)
            Text(model.item.isLogin ? (model.item.target.isEmpty ? model.item.kindLabel : model.item.target) : model.item.kindLabel)
                .font(.subheadline).foregroundStyle(Palette.secondaryText).lineLimit(1)
            if let url = model.item.openableURL {
                Button { openURL(url) } label: { Label("Open website", systemImage: "safari") }
                    .buttonStyle(.bordered).tint(Palette.accent).padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    /// The item's collections as chips, and why a view-only shared item cannot be changed here.
    @ViewBuilder private var collectionsSection: some View {
        Section("Collections") {
            if !collectionNames.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(Array(collectionNames.enumerated()), id: \.offset) { _, name in
                            Label(name, systemImage: "folder").font(.subheadline)
                                .padding(.horizontal, 10).padding(.vertical, 5)
                                .foregroundStyle(Palette.text)
                                .background(.thinMaterial, in: Capsule())
                        }
                    }
                }
            }
            if readOnly {
                Label(EditorModel.readOnlyItemText, systemImage: "lock")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Reads the item's collections (names of those this iPhone knows) and whether it is view-only here.
    private func loadCollections() {
        guard let snap = try? store.load() else { return }
        let ids = Set(CollectionCatalog.memberships(of: model.item.id, in: snap))
        collectionNames = CollectionCatalog.collections(in: snap).filter { ids.contains($0.id) }.map { CollectionCatalog.displayName($0.name) }
        readOnly = EditorModel.itemIsReadOnly(model.item.id, in: snap)
    }

    private var deleteAlertTitle: String {
        deleteResult == .unchanged ? EditorModel.alreadyRemovedMessage : String(localized: "The item could not be deleted on this device.")
    }

    /// A screen pushed on top (access rules, item history, password history) saved this item: the screen shows the
    /// saved item at once, so its rules apply to the next reveal and copy.
    private func itemChanged() {
        let stored = storedItem
        if let next = model.reloaded(stored, concealSecrets: AccessGate.shared.concealsOnOpen(
            stored, setting: AppSettings.shared.concealSecretsInDetail)) {
            model = next
            codeShown = false
            favorite = stored.favorite
        }
        onChange()
    }

    /// The item as stored now (after a favorite toggle), else the one this screen opened with.
    private var storedItem: VaultItem {
        guard let snap = try? store.load() else { return model.item }
        return VaultItem.items(from: snap).first { $0.id == model.item.id } ?? model.item
    }

    /// The star: writes `favorite` and `updated_at` (synced) and reloads the list; the screen stays open.
    private func toggleFavorite() {
        let next = !favorite
        switch VaultListModel.setFavorite(next, id: model.item.id, store: store, clock: SystemClock()) {
        case .saved: favorite = next; onChange()
        case .unchanged: favorite = next
        default: favoriteFailed = true
        }
    }

    /// Deletes a desktop-only item (tombstone, like every delete): `EditorModel.delete`.
    private func deleteNow() {
        let id = model.item.id
        let r = trash?.moveToTrash(id: id)
            ?? EditorModel.delete(id: id, store: store, clock: SystemClock(), background: UIKitBackgroundTasks())
        if r == .saved { trash?.offerUndo(); onChange(); dismiss() } else { deleteResult = r }
    }
}

/// Shows the time left in the current TOTP period.
struct TOTPRing: View {
    let fraction: Double
    let seconds: Int
    var body: some View {
        ZStack {
            Circle().stroke(Palette.separator, lineWidth: 4)
            Circle().trim(from: 0, to: fraction)
                .stroke(seconds <= 7 ? Palette.glowOrange : Palette.accent, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text("\(seconds)").font(.caption2.monospacedDigit()).foregroundStyle(Palette.secondaryText)
        }
        .frame(width: 36, height: 36)
        .accessibilityElement().accessibilityLabel("\(seconds) seconds left")
    }
}
