import SwiftUI
import AppKit
import CoreImage
import UniformTypeIdentifiers
import AppSharedMac
import LGKCore

/// 2FA QR codes in an image file, read with the shared Vision decoder (`TwoFactorQRDecoder`), in memory.
enum QRImageDecoder {
    /// The 2FA payloads in the file, or why there are none.
    static func read(_ url: URL) -> Result<[String], TwoFactorQRDecoder.Failure> {
        do { return .success(try TwoFactorQRDecoder.payloads(inImageData: try MacQRImageInput.data(fromFile: url))) }
        catch let f as TwoFactorQRDecoder.Failure { return .failure(f) }
        catch { return .failure(.unreadable) }
    }

    /// The first `otpauth://` link in the image, or nil.
    static func otpauth(in url: URL) -> String? {
        guard case .success(let payloads) = read(url) else { return nil }
        return payloads.first { $0.lowercased().hasPrefix("otpauth://") }
    }
}

/// One edit at a time in the detail panel: a new item or an existing one, saved through `EditorModel`
/// (which applies the form over the stored record, so fields the form does not show are kept as they were).
/// Why the free plan refused: a fifth item, or adding/changing a 2FA code.
enum ProReason: Equatable, Sendable { case itemLimit, twoFactor, sync, attachments }

@MainActor @Observable
final class MacEditorSession {
    static let noQRMessage = String(localized: "No QR code was found in that image.")
    static let notTOTPQRMessage = String(localized: "That QR code isn't a 2FA setup code.")

    private(set) var model: EditorModel?
    /// The id of the item being edited; nil for a new item.
    private(set) var editingID: String?
    /// The id the last successful save wrote (a new item's id, for selecting it).
    private(set) var lastSavedID: String?
    /// The line under the 2FA field after picking a QR image.
    private(set) var qrMessage: String?
    @ObservationIgnored private var baseline: [String: String] = [:]
    /// The Tags field (comma-separated), every kind.
    var tagsText = ""
    /// Under the Tags field when the tags can't be saved.
    private(set) var tagsError: String?
    /// Under the collections picker (more than 20, or the membership save failed).
    private(set) var collectionsError: String?
    /// The record saved but its memberships did not; Save retries only those.
    private(set) var membershipsPending = false
    /// The known collections a typed item is in (the picker).
    var chosenCollections: Set<String> = []
    @ObservationIgnored private var tagsBaseline = ""
    @ObservationIgnored private var collectionsBaseline: Set<String> = []
    /// Mac-local collections (nil hides the picker).
    @ObservationIgnored var collections: CollectionsModel?

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored let pro: ProModel
    @ObservationIgnored private let onNeedsPro: (ProReason) -> Void
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let random: any RandomSource

    init(store: any ItemStore, pro: ProModel, onNeedsPro: @escaping (ProReason) -> Void,
         clock: any UnixClock = SystemClock(), random: any RandomSource = SystemRandomSource()) {
        self.store = store; self.pro = pro; self.onNeedsPro = onNeedsPro; self.clock = clock; self.random = random
    }

    var isActive: Bool { model != nil }
    var isNew: Bool { model?.isNew ?? false }

    /// Something differs from what the form opened with.
    var isDirty: Bool {
        guard let model else { return false }
        return Self.nonEmpty(model.values) != Self.nonEmpty(baseline) || tagsText != tagsBaseline
            || chosenCollections != collectionsBaseline
    }

    /// Typed items get the collections picker (Windows: logins have no `collection_ids`).
    var showsCollections: Bool { collections != nil && model.map { $0.kind != .web } ?? false }

    private static func nonEmpty(_ v: [String: String]) -> [String: String] { v.filter { !$0.value.isEmpty } }

    static func canEdit(_ item: VaultItem) -> Bool { EditorKind(kind: item.kind) != nil }

    /// False (and `onNeedsPro`) when the free plan has no room for another item.
    func allowsNew() -> Bool {
        if let snap = try? store.load(), !ItemLimit.allows(.create, snapshot: snap, isPro: pro.isPro) {
            onNeedsPro(.itemLimit)
            return false
        }
        return true
    }

    /// Opens an empty form, unless the free plan is full (then `onNeedsPro`).
    @discardableResult func startNew(_ kind: EditorKind) -> Bool {
        guard allowsNew() else { return false }
        open(EditorModel(store: store, pro: pro, editing: nil, kind: kind, clock: clock, random: random,
                        keepsPasswordHistory: true), id: nil)
        return true
    }

    func startEdit(_ item: VaultItem) {
        guard let kind = EditorKind(kind: item.kind) else { return }
        open(EditorModel(store: store, pro: pro, editing: item, kind: kind, clock: clock, random: random,
                        keepsPasswordHistory: true), id: item.id, tags: item.tags)
    }

    private func open(_ m: EditorModel, id: String?, tags: [String] = []) {
        model = m; editingID = id; baseline = m.values; qrMessage = nil; tagsError = nil; collectionsError = nil
        tagsText = CollectionsModel.tagText(tags); tagsBaseline = tagsText
        chosenCollections = id.flatMap { collections?.shownMemberships(of: $0) } ?? []
        collectionsBaseline = chosenCollections
    }

    /// Saves; the form closes on success (or when nothing changed). A full free plan, or a 2FA change on it,
    /// calls `onNeedsPro`.
    @discardableResult func save() -> SaveResult {
        guard let model else { return .failed }
        // The item saved but its collections didn't: Save only retries the collections.
        if membershipsPending {
            guard retryMemberships(kind: model.kind) else { return .failed }
            close(); return .saved
        }
        tagsError = nil; collectionsError = nil
        do { model.tags = tagsText == tagsBaseline ? nil : try CollectionsModel.tags(fromText: tagsText) } catch NormaliseError.rejected(let detail) {
            tagsError = detail; return .invalid
        } catch { tagsError = String(localized: "Check the tags."); return .invalid }
        // Check the memberships first, so a refused one never leaves a half-saved item.
        let membershipsChanged = showsCollections && chosenCollections != collectionsBaseline
        if membershipsChanged, let collections {
            do { _ = try collections.plannedMemberships(of: editingID ?? "", kind: model.kind.rawValue, to: chosenCollections) }
            catch { collectionsError = CollectionsModel.tooManyText; return .invalid }
        }
        let result = model.save()
        switch result {
        case .saved, .unchanged:
            lastSavedID = result == .saved ? (model.savedID ?? editingID) : editingID
            if membershipsChanged && !retryMemberships(kind: model.kind) {
                // Keep the form open on the saved item so Save can retry (Cancel closes; the item stays saved).
                editingID = lastSavedID; membershipsPending = true
                return .failed
            }
            close()
        case .needsPro:
            model.showUpgrade = false
            // EditorModel says needsPro for a full free plan or for a 2FA change; the 2FA error tells them apart.
            onNeedsPro(model.totpError == ProFeatures.totpMessage ? .twoFactor : .itemLimit)
        default: break
        }
        return result
    }

    nonisolated static let membershipsFailedText = String(localized: "Saved, but collections couldn't be updated.")

    /// After the record is saved: false (with the line under the picker) when the memberships couldn't be saved.
    private func retryMemberships(kind: EditorKind) -> Bool {
        guard let collections, let id = lastSavedID else { return true }
        do {
            try collections.setMemberships(of: id, kind: kind.rawValue, to: chosenCollections)
            membershipsPending = false
            return true
        } catch { collectionsError = Self.membershipsFailedText; return false }
    }

    /// Drops the form and any unsaved changes.
    func cancel() { close() }

    private func close() {
        model = nil; editingID = nil; baseline = [:]; qrMessage = nil
        tagsText = ""; tagsBaseline = ""; tagsError = nil; collectionsError = nil; chosenCollections = []; collectionsBaseline = []
        membershipsPending = false
    }

    /// Fills the 2FA field from a QR image file.
    func importQR(from url: URL) {
        guard let model else { return }
        switch QRImageDecoder.read(url) {
        case .failure(.noQRCode): qrMessage = Self.noQRMessage
        case .failure(.notTwoFactor): qrMessage = Self.notTOTPQRMessage
        case .failure(let f): qrMessage = f.message
        case .success(let payloads):
            qrMessage = nil
            model.scanTOTP(payloads.first { $0.lowercased().hasPrefix("otpauth://") } ?? payloads[0])
        }
    }

    /// A key from the Scan QR code sheet for the 2FA field.
    func useScannedKey(_ key: String) {
        qrMessage = nil
        model?.scanTOTP(key)
    }

    /// The scan model behind the editor's Scan QR code sheet.
    func makeScanModel() -> TwoFactorScanModel { TwoFactorScanModel(store: store, pro: pro, clock: clock, random: random) }

    /// Opens a prefilled new login (from a scanned 2FA code); unsaved, so leaving it asks first.
    @discardableResult func startPrefilled(_ m: EditorModel) -> Bool {
        guard allowsNew() else { return false }
        open(m, id: nil)
        baseline = [:]
        return true
    }

    func clearQRMessage() { qrMessage = nil }
}

/// The detail panel in edit mode (Windows behaviour): the item's fields as a form, with Save and Cancel in the
/// header. Logins show Details (title, website), Sign-in (username, password with the generator, 2FA) and Notes.
struct MacEditorView: View {
    @Bindable var session: MacEditorSession
    let model: EditorModel
    let item: VaultItem?
    let onSaved: (String?) -> Void
    let onCancel: () -> Void
    @State private var revealed: Set<String> = []
    @State private var generatorFor: String?
    /// The 2FA field's Scan QR code sheet.
    @State private var scanning: TwoFactorScanModel?
    @Environment(\.macTheme) private var theme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header.padding(.bottom, 2)
                if let error = model.error {
                    Text(error).font(.system(size: 13)).foregroundStyle(theme.danger).padding(.top, 10)
                }
                sections
                organise
            }
            .padding(.horizontal, 18).padding(.vertical, 16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .scrollIndicators(.automatic)
        .softBottomEdge()
        .foregroundStyle(theme.text)
        .font(.system(size: 14))
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 12) {
            if let item { ItemLogo(item: item, size: 40) } else { KindBadge(kind: model.kind, size: 40) }
            VStack(alignment: .leading, spacing: 2) {
                Text(heading).font(.system(size: 18, weight: .semibold)).lineLimit(1)
                Text(model.isNew ? String(localized: "New item") : String(localized: "Editing")).font(.system(size: 13)).foregroundStyle(theme.textMuted)
            }
            Spacer(minLength: 8)
            Button("Cancel", action: onCancel)
                .buttonStyle(PillButtonStyle(primary: false))
                .keyboardShortcut(.cancelAction)
            Button("Save", action: save)
                .buttonStyle(PillButtonStyle(primary: true))
                .help("Save (⌘S)")   // ⌘S is Item › Save in the menu bar
        }
    }

    private var heading: String {
        let t = model.value(model.titleKey)
        if !t.isEmpty { return t }
        return model.isNew ? NewItemMenu.label(model.kind) : (item?.title ?? model.kind.label)
    }

    private func save() {
        if session.save() == .saved || session.model == nil { onSaved(session.lastSavedID) }
    }

    // MARK: sections

    @ViewBuilder private var sections: some View {
        let fields = model.kind.fields
        if model.kind == .web {
            group(String(localized: "Details"), fields.filter { ["label", "origin"].contains($0.key) })
            group(String(localized: "Sign-in"), fields.filter { ["username", "password", "totp"].contains($0.key) })
            group(String(localized: "Notes"), fields.filter { $0.key == "notes" }, labelled: false)
        } else {
            let notes = fields.filter { $0.key == "notes" || ($0.key == "body" && model.kind == .note) }
            group(String(localized: "Details"), fields.filter { f in !notes.contains { $0.key == f.key } })
            if !notes.isEmpty { group(model.kind == .note ? String(localized: "Note") : String(localized: "Notes"), notes, labelled: false) }
        }
    }

    /// Tags for every item; the collections picker for typed items only.
    private var organise: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Organise").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                .padding(.top, 14).padding(.bottom, 6)
                .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("Tags").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                        .frame(width: 120, alignment: .leading).padding(.top, 9)
                    VStack(alignment: .leading, spacing: 4) {
                        TextField("work, finance", text: $session.tagsText).glassField().accessibilityLabel("Tags")
                        Text(session.tagsError ?? String(localized: "Separate tags with commas. Up to 20, each up to 40 characters."))
                            .font(.system(size: 12)).foregroundStyle(session.tagsError == nil ? theme.textFaint : theme.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if session.showsCollections, let collections = session.collections {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text("Collections").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                            .frame(width: 120, alignment: .leading)
                        VStack(alignment: .leading, spacing: 4) {
                            CollectionsPicker(collections: collections.collections, chosen: $session.chosenCollections)
                            if let error = session.collectionsError {
                                Text(error).font(.system(size: 12)).foregroundStyle(theme.danger)
                            }
                        }
                    }
                }
            }
            .padding(12)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
        }
    }

    private func group(_ title: String, _ fields: [EditorKind.Field], labelled: Bool = true) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title).font(.system(size: 12)).foregroundStyle(theme.textFaint)
                .padding(.top, 14).padding(.bottom, 6)
                .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 10) {
                ForEach(fields) { field in
                    if labelled { row(field) } else { control(field) }
                }
            }
            .padding(12)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
        }
    }

    private func row(_ field: EditorKind.Field) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label(field)).font(.system(size: 13)).foregroundStyle(theme.textMuted)
                .frame(width: 120, alignment: .leading).lineLimit(2)
                .padding(.top, field.control == .toggle ? 0 : 9)
                .alignmentGuide(.firstTextBaseline) { $0[.firstTextBaseline] }
            control(field)
        }
    }

    private func label(_ f: EditorKind.Field) -> String {
        switch f.key {
        case "totp": String(localized: "Two-factor")
        case "origin" where model.kind == .web: String(localized: "Website")
        default: f.label
        }
    }

    private func binding(_ key: String) -> Binding<String> {
        Binding(get: { model.value(key) }, set: { model.set(key, $0) })
    }

    @ViewBuilder private func control(_ f: EditorKind.Field) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            switch f.control {
            case .toggle:
                Toggle(f.label, isOn: Binding(get: { model.value(f.key) == "true" }, set: { model.set(f.key, $0 ? "true" : "false") }))
                    .toggleStyle(.switch).labelsHidden().controlSize(.small)
            case .choice(let options):
                Picker(f.label, selection: binding(f.key)) {
                    ForEach(options, id: \.self) { Text(EditorKind.choiceLabel($0)).tag($0) }
                }
                .labelsHidden().fixedSize()
            case .date:
                TextField("YYYY-MM-DD", text: binding(f.key)).glassField()
            case .amount, .text:
                if f.multiline && !(f.secret && !revealed.contains(f.key)) {
                    TextEditor(text: binding(f.key))
                        .font(.system(size: 14, design: f.secret || f.key == "public_key" ? .monospaced : .default))
                        .scrollContentBackground(.hidden)
                        .frame(minHeight: f.key == "body" ? 160 : 84)
                        .padding(.horizontal, 7).padding(.vertical, 6)
                        .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous).strokeBorder(theme.glassBorder))
                        .accessibilityLabel(f.label)
                } else {
                    textField(f)
                }
            }
            if let line = errorLine(f) {
                Text(line).font(.system(size: 12)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
            } else if let hint = hintLine(f) {
                Text(hint).font(.system(size: 12)).foregroundStyle(theme.textFaint).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func textField(_ f: EditorKind.Field) -> some View {
        HStack(spacing: 8) {
            Group {
                if f.secret && !revealed.contains(f.key) {
                    SecureField(placeholder(f), text: binding(f.key))
                } else {
                    TextField(placeholder(f), text: binding(f.key))
                        .font(.system(size: 14, design: f.secret ? .monospaced : .default))
                }
            }
            .glassField()
            .accessibilityLabel(f.label)
            if f.secret {
                Button(revealed.contains(f.key) ? String(localized: "Hide") : String(localized: "Show")) {
                    if revealed.contains(f.key) { revealed.remove(f.key) } else { revealed.insert(f.key) }
                }
                .buttonStyle(.plain).foregroundStyle(theme.link)
            }
            if f.key == "password" {
                Button { generatorFor = f.key } label: {
                    Image(systemName: "wand.and.stars").foregroundStyle(theme.link).frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Generate a password")
                .accessibilityLabel("Generate a password")
                .popover(isPresented: Binding(get: { generatorFor == f.key }, set: { if !$0 { generatorFor = nil } }), arrowEdge: .bottom) {
                    GeneratorPopover(onUse: { value in model.set(f.key, value) }, onClose: { generatorFor = nil })
                }
            }
            if f.key == "totp" {
                Button("Scan QR code…") { scanning = session.makeScanModel() }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
                    .help("Read the setup code from an image, a pasted screenshot or a dropped file")
                    .sheet(item: $scanning) { scan in
                        MacScanSheet(model: scan, onUseKey: { session.useScannedKey($0) }, onClose: { scanning = nil }).macThemed()
                    }
            }
        }
    }

    private func placeholder(_ f: EditorKind.Field) -> String {
        switch f.key {
        case "origin": "example.com"
        case "username": "name@example.com"
        case "totp": String(localized: "Setup key or otpauth:// link")
        case "url": "https://"
        default: ""
        }
    }

    private func errorLine(_ f: EditorKind.Field) -> String? {
        switch f.key {
        case "origin", "url": model.websiteError
        case "totp": session.qrMessage ?? model.totpError
        case "amount_minor": model.amountError
        default: nil
        }
    }

    private func hintLine(_ f: EditorKind.Field) -> String? {
        if f.key == "totp" && model.totpNeedsPro && model.value("totp").isEmpty { return String(localized: "Two-factor codes need LocalGateKeys Pro.") }
        return f.hint
    }

}

/// A new item's placeholder logo: the kind's initial on the accent colour.
struct KindBadge: View {
    let kind: EditorKind
    var size: CGFloat = 40
    @Environment(\.macTheme) private var theme

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
            .fill(theme.accent)
            .overlay(Text(String(NewItemMenu.label(kind).prefix(1))).font(.system(size: size * 0.42, weight: .semibold))
                .foregroundStyle(theme.onAccent))
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}
