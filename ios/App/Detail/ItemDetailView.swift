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
    @Environment(\.dismiss) private var dismiss
    @Environment(\.phoneTrash) private var trash
    @Environment(\.phoneReminders) private var reminders

    init(item: VaultItem, store: any ItemStore, pro: ProModel, onChange: @escaping () -> Void) {
        _model = State(initialValue: ItemDetailModel(item: item, clipboard: SecretClipboard.shared, clock: SystemClock(),
                                                         concealSecrets: AppSettings.shared.concealSecretsInDetail))
        _favorite = State(initialValue: item.favorite)
        self.store = store; self.pro = pro; self.onChange = onChange
    }

    @Environment(\.openURL) private var openURL
    /// "Show on Apple Watch" (UX workstream 12): the limit or Pro message after a tap.
    @State private var watchMessage: String?

    /// Pins or unpins this item's 2FA code on the Apple Watch app. Shown only with a paired watch that has
    /// the app installed (or when already pinned, so it can be unpinned).
    @ViewBuilder private var watchPinRow: some View {
        let watch = WatchCodes.shared
        let pinned = watch.isPinned(model.item.id)
        if watch.watchAvailable || pinned {
            Button {
                guard let snapshot = try? store.load() else { return }
                switch watch.toggle(model.item.id, snapshot: snapshot, isPro: pro.isPro) {
                case .pinned: watchMessage = nil; CopyToast.shared.show(String(localized: "Sent to Apple Watch"))
                case .unpinned: watchMessage = nil; CopyToast.shared.show(String(localized: "Removed from Apple Watch"))
                case .limitReached: watchMessage = String(localized: "Up to \(WatchMessage.maxPins) codes can be on Apple Watch. Remove one first.")
                case .needsPro: watchMessage = String(localized: "Apple Watch codes are part of Pro, like all 2FA.")
                }
            } label: {
                Label(pinned ? String(localized: "Remove from Apple Watch") : String(localized: "Show on Apple Watch"),
                      systemImage: pinned ? "applewatch.slash" : "applewatch")
            }
            .foregroundStyle(Palette.accentText)
            if let watchMessage {
                Text(watchMessage).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        }
    }

    var body: some View {
        List {
            Section { header }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            if let totp = model.totp {
                Section("One-time code") {
                    HStack(spacing: 16) {
                        TOTPRing(fraction: totp.fractionRemaining, seconds: totp.secondsRemaining)
                        Text(totp.code).font(.system(.title, design: .monospaced)).foregroundStyle(Palette.text)
                        Spacer()
                        Button { if model.copyTOTP() { CopyToast.shared.show(String(localized: "Code copied")) } } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless).accessibilityLabel("Copy code")
                    }
                    watchPinRow
                }
                .listRowBackground(Palette.groupSurface)
            }
            Section {
                ForEach(model.fields) { field in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.label).font(.caption).foregroundStyle(Palette.secondaryText)
                        HStack(alignment: .firstTextBaseline) {
                            Text(model.displayValue(field))
                                .font(field.isSecret ? .system(.body, design: .monospaced) : .body)
                                .foregroundStyle(Palette.text).textSelection(.disabled)
                            Spacer()
                            if field.isSecret {
                                Button { model.toggleReveal(field) } label: {
                                    Image(systemName: model.isRevealed(field) ? "eye.slash" : "eye")
                                }
                                .buttonStyle(.borderless)
                                .disabled(model.screenCaptured)
                                .accessibilityLabel(model.isRevealed(field) ? String(localized: "Hide") : String(localized: "Reveal"))
                            }
                            Button { model.copy(field); CopyToast.shared.show(String(localized: "\(field.label) copied")) } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).accessibilityLabel("Copy \(field.label)")
                        }
                        if field.id == "password" {
                            StrengthMeter(level: GeneratorStrength.estimate(password: field.value)).padding(.top, 2)
                        }
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
            if model.item.kind == AttachmentDocuments.kind {
                DocumentSection(item: model.item, store: store, onChange: onChange)
            }
            if model.item.kind == "web" {
                let count = PasswordHistory.entries(model.item.record).count
                Section {
                    NavigationLink {
                        PasswordHistoryView(item: model.item, store: store, onChange: onChange)
                    } label: {
                        LabeledContent("Password history", value: count == 0 ? String(localized: "None") : "\(count)")
                    }
                    .disabled(count == 0)
                }
                .listRowBackground(Palette.groupSurface)
            }
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
            }
            if Share.canShare(model.item.record) {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { sharing = true } label: { Image(systemName: "square.and.arrow.up") }
                        .accessibilityLabel("Share")
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                // Other kinds are read-only on the phone and kept intact.
                if EditorKind(kind: model.item.kind) != nil { Button("Edit") { editing = true } }
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
                 ? String(localized: "The item and its file are removed from this iPhone and from your other devices at the next sync.")
                 : String(localized: "It is removed from this iPhone and from your other devices at the next sync. It can only be edited on your PC."))
        }
        .alert(deleteAlertTitle, isPresented: Binding(get: { deleteResult == .unchanged || deleteResult == .failed },
                                                      set: { if !$0 { deleteResult = nil } })) {
            Button("OK") {
                if deleteResult == .unchanged { onChange(); dismiss() }
                deleteResult = nil
            }
        }
        .alert("The favorite could not be saved on this device.", isPresented: $favoriteFailed) { Button("OK") {} }
        .sheet(isPresented: $sharing) { ShareItemSheet(item: storedItem) }
        .sheet(isPresented: $editingPasskey) {
            PasskeyEditView(model: PasskeyRenameModel(store: store, item: storedItem, clock: SystemClock())) { result in
                if result == .saved { onChange(); dismiss() }
            }
        }
        .onReceive(ticker) { _ in model.tick() }
        .onChange(of: ScreenCaptureMonitor.shared.isCaptured, initial: true) { _, captured in model.screenCaptured = captured }
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

    private var deleteAlertTitle: String {
        deleteResult == .unchanged ? EditorModel.alreadyRemovedMessage : String(localized: "The item could not be deleted on this device.")
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
