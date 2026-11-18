import SwiftUI
import AppShared

/// Where Settings › Travel mode reports a saved change (RootTabs refreshes the list, widgets, watch and AutoFill).
@MainActor
final class TravelSettingsRoute {
    static let shared = TravelSettingsRoute()
    var onChange: () -> Void = {}
}

/// The rules of the Travel mode screen, apart from SwiftUI.
@MainActor
enum TravelModeActions {
    enum Outcome: Equatable { case saved, needsPro, unavailable, invalid, needsOwner }

    /// Saves `next` into this unlock's local data. Turning it on or changing what it hides needs Pro; turning it off
    /// never does. `since` is set when it goes from off to on. A change that can show a hidden item (off, or a
    /// collection or tag dropped from the set) is refused with `.needsOwner` unless the owner confirmed it first.
    static func save(_ next: TravelMode, local: (any PhoneLocalHosting)?, isPro: Bool, now: Int64,
                     ownerConfirmed: Bool = false) -> Outcome {
        guard let local, var data = local.localData else { return .unavailable }
        let current = data.travel
        if current.changeNeedsPro(to: next), !isPro { return .needsPro }
        if current.revealsHidden(to: next), !ownerConfirmed { return .needsOwner }
        var value = next
        if value.on && !current.on { value.since = now }
        if !value.on { value.since = current.since }
        guard let valid = try? value.validated() else { return .invalid }
        data.travelMode = valid
        do { try local.commitLocalData(data) } catch { return .unavailable }
        return .saved
    }

    /// The tags used by live items, one per folded form, in a stable order.
    static func tags(in snapshot: StoreSnapshot) -> [String] {
        var seen = Set<[UInt32]>()
        var out: [String] = []
        for subject in TravelMode.subjects(in: snapshot) {
            for tag in subject.tags where seen.insert(RecordDigest.foldKey(tag)).inserted { out.append(tag) }
        }
        return out.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }
}

/// Settings › Travel mode (feature pack §2, Pro): hide chosen collections and tags on this iPhone only.
struct TravelModeView: View {
    let store: any ItemStore
    let pro: ProModel
    @State private var draft = TravelMode.off
    @State private var saved = TravelMode.off
    @State private var collections: [CollectionCatalog.Collection] = []
    @State private var tags: [String] = []
    @State private var hiddenCount = 0
    @State private var message: String?
    @State private var showUpgrade = false

    var body: some View {
        List {
            Section {
                Toggle("Travel mode", isOn: Binding(get: { draft.on }, set: { turn($0) }))
                    .tint(Palette.accent)
                if saved.on {
                    Text("\(hiddenCount) items are hidden on this device.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
            } footer: {
                Text("Hides the chosen collections and tags on this device only: in the list, search, AutoFill, widgets, Apple Watch and unencrypted exports. Nothing is deleted, hidden items keep syncing, and your other devices still show them. It is not a way to hide items from someone who can unlock this device.")
            }
            .listRowBackground(Palette.groupSurface)
            Section("Collections") {
                if collections.isEmpty { Text("No collections yet.").foregroundStyle(Palette.secondaryText) }
                ForEach(collections, id: \.id) { c in
                    Toggle(CollectionCatalog.displayName(c.name), isOn: Binding(
                        get: { draft.collections.contains { $0.lowercased() == c.id.lowercased() } },
                        set: { on in
                            draft.collections.removeAll { $0.lowercased() == c.id.lowercased() }
                            if on { draft.collections.append(c.id.lowercased()) }
                        }))
                    .tint(Palette.accent)
                    .disabled(!on(collectionLimitFor: c.id))
                }
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                if tags.isEmpty { Text("No tags yet.").foregroundStyle(Palette.secondaryText) }
                ForEach(tags, id: \.self) { tag in
                    Toggle(tag, isOn: Binding(
                        get: { draft.tags.contains { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) } },
                        set: { on in
                            draft.tags.removeAll { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) }
                            if on { draft.tags.append(tag) }
                        }))
                    .tint(Palette.accent)
                    .disabled(!draft.tags.contains { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) } && draft.tags.count >= TravelMode.maxTags)
                }
            } header: {
                Text("Tags")
            } footer: {
                Text("Logins are hidden by tag; other items by collection or tag.")
            }
            .listRowBackground(Palette.groupSurface)
            if draft != saved && draft.on {
                Section {
                    Button("Save") { save(draft) }.foregroundStyle(Palette.accentText)
                }
                .listRowBackground(Palette.groupSurface)
            }
            if let message {
                Text(message).font(.footnote).foregroundStyle(Palette.secondaryText).listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Travel mode")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: reload)
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
    }

    private func on(collectionLimitFor id: String) -> Bool {
        draft.collections.contains { $0.lowercased() == id.lowercased() } || draft.collections.count < TravelMode.maxCollections
    }

    private func reload() {
        saved = HistoryRecorder.shared.host?.localData?.travel ?? .off
        draft = saved
        guard let snap = try? store.load() else { return }
        collections = CollectionCatalog.collections(in: snap)
        tags = TravelModeActions.tags(in: snap)
        hiddenCount = saved.hiddenIDs(in: snap).count
    }

    private func turn(_ on: Bool) {
        if on {
            var next = draft
            next.on = true
            draft = next
            if next.collections.isEmpty && next.tags.isEmpty {
                message = String(localized: "Choose collections or tags to hide, then tap Save.")
            } else {
                save(next)
            }
        } else if saved.on {
            // Turning it off shows hidden items again: the owner confirms first (Face ID, Touch ID or the passcode).
            Task {
                guard await AppPasswordGate.confirmOwner(String(localized: "Turn off travel mode")) else { return }
                var next = saved
                next.on = false
                save(next, ownerConfirmed: true)
            }
        } else {
            draft.on = false
        }
    }

    private func save(_ next: TravelMode, ownerConfirmed: Bool = false) {
        switch TravelModeActions.save(next, local: HistoryRecorder.shared.host, isPro: pro.isPro,
                                      now: Int64(Date().timeIntervalSince1970), ownerConfirmed: ownerConfirmed) {
        case .needsOwner:
            // Dropping a hidden collection or tag shows items again (scan 2026-11-15 S-M4): the owner confirms first,
            // as for turning travel mode off.
            Task {
                guard await AppPasswordGate.confirmOwner(String(localized: "Show hidden items again")) else { return }
                save(next, ownerConfirmed: true)
            }
        case .saved:
            message = nil
            TravelSettingsRoute.shared.onChange()
            reload()
        case .needsPro:
            draft = saved
            message = String(localized: "Travel mode is part of Pro.")
            showUpgrade = true
        case .invalid:
            message = String(localized: "Up to 20 collections and 20 tags can be hidden.")
        case .unavailable:
            draft = saved
            message = String(localized: "Travel mode could not be saved on this device. Try again.")
        }
    }
}
