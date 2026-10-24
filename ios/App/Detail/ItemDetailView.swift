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
    @Environment(\.dismiss) private var dismiss

    init(item: VaultItem, store: any ItemStore, pro: ProModel, onChange: @escaping () -> Void) {
        _model = State(initialValue: ItemDetailModel(item: item, clipboard: .shared, clock: SystemClock(),
                                                         concealSecrets: AppSettings.shared.concealSecretsInDetail))
        self.store = store; self.pro = pro; self.onChange = onChange
    }

    @Environment(\.openURL) private var openURL

    var body: some View {
        List {
            Section { header }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            if let totp = model.totp {
                Section("One-time code") {
                    HStack(spacing: 16) {
                        TOTPRing(fraction: totp.fractionRemaining, seconds: totp.secondsRemaining)
                        Text(totp.code).font(.system(.title, design: .monospaced)).foregroundStyle(Palette.text)
                        Spacer()
                        Button { if model.copyTOTP() { CopyToast.shared.show("Code copied") } } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless).accessibilityLabel("Copy code")
                    }
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
                                .accessibilityLabel(model.isRevealed(field) ? "Hide" : "Reveal")
                            }
                            Button { model.copy(field); CopyToast.shared.show("\(field.label) copied") } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).accessibilityLabel("Copy \(field.label)")
                        }
                        if field.id == "password" {
                            StrengthMeter(level: GeneratorStrength.estimate(password: field.value)).padding(.top, 2)
                        }
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
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
                // Other kinds are read-only on the phone and kept intact.
                if EditorKind(kind: model.item.kind) != nil { Button("Edit") { editing = true } }
                else if model.item.kind == "passkey" { Button("Edit") { editingPasskey = true } }
                else if ItemDetailModel.offersDeleteOnly(kind: model.item.kind) {
                    Button("Delete", role: .destructive) { confirmDelete = true }
                }
            }
        }
        .confirmationDialog("Delete this item?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { deleteNow() }
        } message: {
            Text("It is removed from this iPhone and from your other devices at the next sync. It can only be edited on your PC.")
        }
        .alert(deleteAlertTitle, isPresented: Binding(get: { deleteResult == .unchanged || deleteResult == .failed },
                                                      set: { if !$0 { deleteResult = nil } })) {
            Button("OK") {
                if deleteResult == .unchanged { onChange(); dismiss() }
                deleteResult = nil
            }
        }
        .sheet(isPresented: $editingPasskey) {
            PasskeyEditView(model: PasskeyRenameModel(store: store, item: model.item, clock: SystemClock())) { result in
                if result == .saved { onChange(); dismiss() }
            }
        }
        .onReceive(ticker) { _ in model.tick() }
        .onChange(of: ScreenCaptureMonitor.shared.isCaptured, initial: true) { _, captured in model.screenCaptured = captured }
        .sheet(isPresented: $editing) {
            // Editing and deleting are never limited, even over the free plan's item count.
            EditorView(model: EditorModel(store: store, pro: pro, editing: model.item,
                                          kind: EditorKind(kind: model.item.kind) ?? .note,
                                          clock: SystemClock(), random: SystemRandomSource()),
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
        deleteResult == .unchanged ? EditorModel.alreadyRemovedMessage : "The item could not be deleted on this device."
    }

    /// Deletes a desktop-only item (tombstone, like every delete): `EditorModel.delete`.
    private func deleteNow() {
        let r = EditorModel.delete(id: model.item.id, store: store, clock: SystemClock(), background: UIKitBackgroundTasks())
        if r == .saved { onChange(); dismiss() } else { deleteResult = r }
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
