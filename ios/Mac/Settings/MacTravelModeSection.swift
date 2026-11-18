import SwiftUI
import LocalAuthentication
import AppSharedMac

/// The rules of Settings › Security › Travel mode on this Mac (feature pack §2), apart from SwiftUI; the iPhone's
/// `TravelModeActions` with the Mac's local data.
@MainActor
enum MacTravelMode {
    enum Outcome: Equatable { case saved, needsPro, unavailable, invalid, needsOwner }

    /// Saves `next` into this unlock's local data. Turning it on or changing what it hides needs Pro; turning it off
    /// never does. `since` is set when it goes from off to on. A duress session saves nothing (§2: hidden there). A
    /// change that can show a hidden item (off, or a collection or tag dropped from the set) is refused with
    /// `.needsOwner` unless the owner confirmed it first (scan 2026-11-15 S-M4).
    static func save(_ next: TravelMode, local: (any LocalDataHosting)?, isPro: Bool, now: Int64,
                     duress: Bool = DuressSession.shared.isOpen, ownerConfirmed: Bool = false) -> Outcome {
        guard !duress, let local, var data = local.localData else { return .unavailable }
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

    /// The tags used by live items, one per folded form, sorted.
    static func tags(in snapshot: StoreSnapshot) -> [String] {
        var seen = Set<[UInt32]>()
        var out: [String] = []
        for subject in TravelMode.subjects(in: snapshot) {
            for tag in subject.tags where seen.insert(RecordDigest.foldKey(tag)).inserted { out.append(tag) }
        }
        return out.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    /// Touch ID or the Mac's login password, asked again for this step (turning travel mode off, or dropping a hidden
    /// collection or tag, shows hidden items).
    static func confirmOwner(_ reason: String = String(localized: "Turn off travel mode")) async -> Bool {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication,
                                              localizedReason: reason.prefix(1).lowercased() + reason.dropFirst())) ?? false
    }

    static var note: String {
        String(localized: "Hides the chosen collections and tags on this Mac only: in the list, search, the menu bar, AutoFill and unencrypted exports. Nothing is deleted, hidden items keep syncing, and your other devices still show them. It is not a way to hide items from someone who can unlock this Mac.")
    }

    static var terms: SettingsRowText { SettingsRowText(title: String(localized: "Travel mode"), detail: note) }
}

/// Settings › Security › Travel mode (Pro): the switch, then the collections and tags it hides, and Save. Turning it
/// off asks for Touch ID or the Mac's login password. Not shown in a duress session (MacSettingsView).
struct MacTravelModeSection: View {
    let local: any LocalDataHosting
    let store: any ItemStore
    let pro: ProModel
    let onNeedsPro: () -> Void
    @State private var draft = TravelMode.off
    @State private var saved = TravelMode.off
    @State private var collections: [CollectionCatalog.Collection] = []
    @State private var tags: [String] = []
    @State private var hiddenCount = 0
    @State private var message: String?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Travel mode").font(.system(size: 13)).foregroundStyle(theme.text)
                    Text(MacTravelMode.note).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                Toggle("", isOn: Binding(get: { draft.on }, set: { turn($0) })).toggleStyle(.switch).labelsHidden()
                    .accessibilityLabel(String(localized: "Travel mode"))
            }
            if saved.on {
                Text("\(hiddenCount) items are hidden on this device.").font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            if draft.on {
                Text("Collections").font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                    .accessibilityAddTraits(.isHeader)
                if collections.isEmpty { Text("No collections yet.").font(.system(size: 12.5)).foregroundStyle(theme.textMuted) }
                ForEach(collections, id: \.id) { c in
                    Toggle(CollectionCatalog.displayName(c.name), isOn: Binding(
                        get: { draft.collections.contains { $0.lowercased() == c.id.lowercased() } },
                        set: { on in
                            draft.collections.removeAll { $0.lowercased() == c.id.lowercased() }
                            if on { draft.collections.append(c.id.lowercased()) }
                        }))
                    .toggleStyle(.checkbox).font(.system(size: 13))
                    .disabled(!draft.collections.contains { $0.lowercased() == c.id.lowercased() }
                              && draft.collections.count >= TravelMode.maxCollections)
                }
                Text("Tags").font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                    .accessibilityAddTraits(.isHeader)
                if tags.isEmpty { Text("No tags yet.").font(.system(size: 12.5)).foregroundStyle(theme.textMuted) }
                ForEach(tags, id: \.self) { tag in
                    Toggle(tag, isOn: Binding(
                        get: { draft.tags.contains { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) } },
                        set: { on in
                            draft.tags.removeAll { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) }
                            if on { draft.tags.append(tag) }
                        }))
                    .toggleStyle(.checkbox).font(.system(size: 13))
                    .disabled(!draft.tags.contains { RecordDigest.foldKey($0) == RecordDigest.foldKey(tag) } && draft.tags.count >= TravelMode.maxTags)
                }
                Text("Logins are hidden by tag; other items by collection or tag.").font(.system(size: 11)).foregroundStyle(theme.textMuted)
                if draft != saved {
                    HStack {
                        Spacer()
                        Button(String(localized: "Cancel")) { reload() }
                        Button(String(localized: "Save")) { save(draft) }.keyboardShortcut(.defaultAction)
                    }
                }
            }
            if let message {
                Text(message).font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .onAppear(perform: reload)
    }

    private func reload() {
        saved = local.localData?.travel ?? .off
        draft = saved
        guard let snap = try? store.load() else { return }
        collections = CollectionCatalog.collections(in: snap)
        tags = MacTravelMode.tags(in: snap)
        hiddenCount = saved.hiddenIDs(in: snap).count
    }

    private func turn(_ on: Bool) {
        if on {
            guard pro.isPro else { message = String(localized: "Travel mode is part of Pro."); onNeedsPro(); return }
            var next = draft
            next.on = true
            draft = next
            if next.collections.isEmpty && next.tags.isEmpty {
                message = String(localized: "Choose collections or tags to hide, then click Save.")
            } else {
                save(next)
            }
        } else if saved.on {
            // Turning it off shows hidden items again: the owner confirms first (Touch ID or the Mac's login password).
            Task {
                guard await MacTravelMode.confirmOwner() else { return }
                var next = saved
                next.on = false
                save(next, ownerConfirmed: true)
            }
        } else {
            draft.on = false
            message = nil
        }
    }

    private func save(_ next: TravelMode, ownerConfirmed: Bool = false) {
        switch MacTravelMode.save(next, local: local, isPro: pro.isPro, now: Int64(Date().timeIntervalSince1970),
                                  ownerConfirmed: ownerConfirmed) {
        case .needsOwner:
            // Dropping a hidden collection or tag shows items again: the owner confirms first, as for turning it off.
            Task {
                guard await MacTravelMode.confirmOwner(String(localized: "Show hidden items again")) else { return }
                save(next, ownerConfirmed: true)
            }
        case .saved:
            message = nil
            reload()
        case .needsPro:
            draft = saved
            message = String(localized: "Travel mode is part of Pro.")
            onNeedsPro()
        case .invalid:
            message = String(localized: "Up to 20 collections and 20 tags can be hidden.")
        case .unavailable:
            draft = saved
            message = String(localized: "Travel mode could not be saved on this device. Try again.")
        }
    }
}
