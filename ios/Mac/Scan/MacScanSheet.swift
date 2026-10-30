import SwiftUI
import AppKit
import UniformTypeIdentifiers
import AppSharedMac
import LGKCore

/// Where a QR image comes from on the Mac (no camera, by design): an image file chosen in the open panel (the
/// sandbox grants that file), a dragged file or image, or an image on the clipboard. The bytes are read into
/// memory, bounded, decoded off the main actor and dropped; nothing is written to disk.
enum MacQRImageInput {
    static let panelMessage = String(localized: "Choose an image or screenshot of the 2FA QR code")
    static let noImageOnClipboard = String(localized: "There is no image on the clipboard. Copy a screenshot of the QR code (⌃⇧⌘4), then paste.")

    @MainActor static func chooseFile() -> URL? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = panelMessage
        panel.prompt = String(localized: "Scan")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// The file's bytes, refused above the decoder's size limit before reading.
    static func data(fromFile url: URL) throws -> Data {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        // A file whose size cannot be read is refused, never read unbounded.
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize else { throw TwoFactorQRDecoder.Failure.unreadable }
        guard size <= TwoFactorQRDecoder.maxImageBytes else { throw TwoFactorQRDecoder.Failure.tooLarge }
        guard let data = try? Data(contentsOf: url) else { throw TwoFactorQRDecoder.Failure.unreadable }
        return data
    }

    enum Pasted: Sendable { case file(URL), image(Data) }

    /// An image on the pasteboard (a copied image file, read later off the main actor, or image data), or nil.
    @MainActor static func pasted(from pasteboard: NSPasteboard) -> Pasted? {
        if let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingContentsConformToTypes: [UTType.image.identifier]]) as? [URL],
           let url = urls.first { return .file(url) }
        for type in [NSPasteboard.PasteboardType.png, .tiff, NSPasteboard.PasteboardType("public.jpeg"), NSPasteboard.PasteboardType("public.heic")] {
            if let d = pasteboard.data(forType: type) { return .image(d) }
        }
        return nil
    }

    /// Loads (a file read happens here, off the main actor) and decodes.
    static func decode(_ load: @escaping @Sendable () throws -> Data) async -> Result<[String], TwoFactorQRDecoder.Failure> {
        await Task.detached(priority: .userInitiated) {
            do { return .success(try TwoFactorQRDecoder.payloads(inImageData: try load())) }
            catch let f as TwoFactorQRDecoder.Failure { return .failure(f) }
            catch { return .failure(.unreadable) }
        }.value
    }
}

/// The Mac's "Scan QR code" sheet (New item menu, ⌘K, the editor's 2FA field). Choose image…, ⌘V or a drop
/// read the code; then one key goes to a login (or a new login, opened in the editor after the sheet has
/// gone), or an export's accounts are chosen and imported. In the editor (`onUseKey`) a key fills the field.
struct MacScanSheet: View {
    @Bindable var model: TwoFactorScanModel
    /// Field mode: the editor's 2FA field takes the key (an export's account is picked first).
    var onUseKey: ((String) -> Void)? = nil
    /// Vault mode: the prefilled new login (opened by the window once this sheet has gone).
    var onNewLogin: (EditorModel) -> Void = { _ in }
    var onSaved: (String) -> Void = { _ in }
    let onClose: () -> Void
    @State private var reading = false
    @State private var dropTargeted = false
    @State private var importing = false
    @State private var decoding: Task<Void, Never>?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "qrcode.viewfinder").font(.system(size: 20)).foregroundStyle(theme.accent)
                Text(onUseKey == nil ? String(localized: "Scan QR code") : String(localized: "Scan 2FA QR code")).font(.system(size: 19, weight: .semibold))
            }
            content
        }
        .padding(22)
        .frame(width: 560)
        .background(WashBackground())
        .foregroundStyle(theme.text)
        .onChange(of: model.step) { _, step in follow(step) }
        .onDisappear { decoding?.cancel(); model.reset() }
        .alert("Replace the 2FA code?", isPresented: Binding(get: { model.confirmReplaceID != nil }, set: { if !$0 { model.cancelReplacements() } })) {
            Button("Replace", role: .destructive) { if let id = model.confirmReplaceID { addKey(id, confirmed: true) } }
            Button("Cancel", role: .cancel) { model.cancelReplacements() }
        } message: { Text("This login already has a 2FA code. The scanned code replaces it.") }
        .alert("Replace 2FA codes?", isPresented: Binding(get: { model.replaceQuestion != nil }, set: { if !$0 { model.cancelReplacements() } })) {
            Button("Replace", role: .destructive) { model.confirmReplacements(); importSelected() }
            Button("Cancel", role: .cancel) { model.cancelReplacements() }
        } message: { Text("These logins already have a 2FA code that will be replaced: \((model.replaceQuestion ?? []).joined(separator: ", ")).") }
    }

    @ViewBuilder private var content: some View {
        switch model.step {
        case .scanning, .newLogin: input(Self.intro)
        case .nextPart(let received, let total):
            input(String(localized: "Part \(received) of \(total) of this export was read. Show the next QR code in your authenticator app, then add its image."))
        case .chooseLogin(let account, let matches): chooser(account, matches)
        case .checklist: onUseKey == nil ? AnyView(checklist) : AnyView(pickOne)
        case .finished(let summary):
            Label(summary, systemImage: "checkmark.circle").font(.system(size: 14)).foregroundStyle(theme.text)
                .fixedSize(horizontal: false, vertical: true)
            HStack { Spacer(); Button("Done", action: close).buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction) }
        }
    }

    static let intro = String(localized: "Use the QR code a website shows when you turn on two-factor authentication, or a Google Authenticator export (Transfer accounts › Export). Choose an image, paste a screenshot with ⌘V, or drop an image here.")

    private func input(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(text).font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 10) {
                Image(systemName: reading ? "hourglass" : "photo.badge.arrow.down").font(.system(size: 30)).foregroundStyle(theme.accent)
                Text(reading ? String(localized: "Reading the image…") : String(localized: "Drop an image of the QR code here")).font(.system(size: 13)).foregroundStyle(theme.textMuted)
            }
            .frame(maxWidth: .infinity, minHeight: 150)
            .background(theme.card.opacity(dropTargeted ? 0.9 : 0.5), in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous)
                .strokeBorder(dropTargeted ? theme.accent : theme.panelBorder, style: StrokeStyle(lineWidth: 1.5, dash: [6, 4])))
            .onDrop(of: [.fileURL, .image], isTargeted: $dropTargeted, perform: drop)
            if let error = model.error {
                Text(error).font(.system(size: 12.5)).foregroundStyle(theme.warning).fixedSize(horizontal: false, vertical: true)
            }
            if let notice = model.notice {
                Text(notice).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
            Text("The image is read on this Mac and is not saved.").font(.system(size: 12)).foregroundStyle(theme.textFaint)
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Paste image", action: paste).buttonStyle(GlassButtonStyle()).keyboardShortcut("v", modifiers: .command)
                Button("Choose image…", action: choose).buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
            }
            .disabled(reading)
        }
    }

    private func chooser(_ account: OTPAccount, _ matches: [ScanLoginMatch]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(Self.line(account)).font(.system(size: 15, weight: .semibold))
            Text("Add this 2FA key to one of these logins, or create a new login for it.").font(.system(size: 13)).foregroundStyle(theme.textMuted)
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(matches) { m in
                        Button { addKey(m.id) } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(m.title.isEmpty ? m.site : m.title).font(.system(size: 14))
                                    Text([m.username, m.site].filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.system(size: 12)).foregroundStyle(theme.textMuted)
                                }
                                Spacer()
                                if m.hasKey { Text("(replaces its 2FA code)").font(.system(size: 11.5)).foregroundStyle(theme.warning) }
                                Text("Add key").font(.system(size: 12.5)).foregroundStyle(theme.link)
                            }
                            .padding(.horizontal, 12).padding(.vertical, 9)
                            .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(maxHeight: 260)
            if let error = model.error { Text(error).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Create a new login", action: newLogin).buttonStyle(AccentButtonStyle())
            }
        }
    }

    private var checklist: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(model.accounts.count) accounts in this export. Choose where each one goes. A new login needs its website; it gets a generated password and the tag needs-password until you set the real one.")
                .font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if let notice = model.notice { Text(notice).font(.system(size: 12.5)).foregroundStyle(theme.textMuted) }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(model.accounts.enumerated()), id: \.offset) { i, a in exportRow(i, a) }
                    ForEach(Array(model.skipped.enumerated()), id: \.offset) { _, s in
                        Text("\([s.issuer, s.account].filter { !$0.isEmpty }.joined(separator: " — ")): \(s.reason)")
                            .font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 320)
            if let error = model.error { Text(error).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button(importing ? String(localized: "Adding…") : (model.selected.count == 1 ? String(localized: "Add 1 account") : String(localized: "Add \(model.selected.count) accounts")),
                       action: importSelected)
                    .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(!model.canAdd || importing)
            }
        }
    }

    @ViewBuilder private func exportRow(_ i: Int, _ a: OTPAccount) -> some View {
        let checked = model.selected.contains(i)
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Toggle(isOn: Binding(get: { checked }, set: { if $0 { model.selected.insert(i) } else { model.selected.remove(i) } })) {
                    Text(Self.line(a)).font(.system(size: 13.5))
                }
                .toggleStyle(.checkbox)
                Spacer()
                if checked, model.rows.indices.contains(i) {
                    Picker("", selection: $model.rows[i].target) {
                        Text("New login").tag(TwoFactorScanModel.Destination.newLogin)
                        ForEach(model.rows[i].matches) { m in
                            Text(m.hasKey ? String(localized: "Add to \(m.title.isEmpty ? m.site : m.title) (replaces its 2FA code)")
                                 : String(localized: "Add to \(m.title.isEmpty ? m.site : m.title)"))
                                .tag(TwoFactorScanModel.Destination.existing(m.id))
                        }
                    }
                    .labelsHidden().frame(maxWidth: 260)
                }
            }
            if checked, model.rows.indices.contains(i), model.rows[i].target == .newLogin {
                HStack(spacing: 8) {
                    TextField("Website, e.g. example.com", text: $model.rows[i].website).textFieldStyle(.roundedBorder)
                    if let suggestion = model.rows[i].suggestion, model.rows[i].website.isEmpty {
                        Button("From the QR code: \(suggestion) — use it?") { model.rows[i].website = suggestion }
                            .buttonStyle(.plain).foregroundStyle(theme.link).font(.system(size: 12))
                    }
                }
                .padding(.leading, 22)
            }
        }
        .padding(.vertical, 3)
    }

    /// Field mode with an export: the account whose key goes into the field.
    private var pickOne: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This export holds \(model.accounts.count) accounts. Choose the one for this login.")
                .font(.system(size: 13)).foregroundStyle(theme.textMuted)
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(Array(model.accounts.enumerated()), id: \.offset) { _, a in
                        Button { use(a.uri) } label: {
                            HStack { Text(Self.line(a)).font(.system(size: 13.5)); Spacer(); Text("Use").foregroundStyle(theme.link) }
                                .padding(.horizontal, 12).padding(.vertical, 8)
                                .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(maxHeight: 280)
            HStack { Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction); Spacer() }
        }
    }

    static func line(_ a: OTPAccount) -> String {
        let s = [a.issuer, a.account].filter { !$0.isEmpty }.joined(separator: " — ")
        return s.isEmpty ? String(localized: "Unnamed account") : s
    }

    // MARK: actions

    private func follow(_ step: TwoFactorScanModel.Step) {
        if let onUseKey {
            switch step {
            case .chooseLogin, .newLogin:
                if let key = model.scannedKey { model.reset(); onUseKey(key); onClose() }
            default: break
            }
            return
        }
        if case .newLogin = step { newLogin() }
    }

    private func newLogin() {
        guard let editor = model.newLoginEditor() else { return }
        model.reset()
        onNewLogin(editor)
        onClose()
    }

    private func use(_ key: String) { model.reset(); onUseKey?(key); onClose() }

    private func addKey(_ id: String, confirmed: Bool = false) {
        if model.addKey(to: id, confirmed: confirmed) == .saved, case .finished(let summary) = model.step { onSaved(summary) }
    }

    private func importSelected() {
        importing = true
        Task {
            let summary = await model.importSelected()
            importing = false
            if let summary { onSaved(summary) }
        }
    }

    private func choose() {
        guard let url = MacQRImageInput.chooseFile() else { return }
        read { try MacQRImageInput.data(fromFile: url) }
    }

    private func paste() {
        switch MacQRImageInput.pasted(from: .general) {
        case .file(let url)?: read { try MacQRImageInput.data(fromFile: url) }
        case .image(let data)?:
            guard data.count <= TwoFactorQRDecoder.maxImageBytes else { model.failed(.tooLarge); return }
            read { data }
        case nil: model.failed(message: MacQRImageInput.noImageOnClipboard)
        }
    }

    private func drop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        let generation = model.generation
        if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                Task { @MainActor in
                    guard generation == model.generation else { return }
                    guard let url else { model.failed(.unreadable); return }
                    read { try MacQRImageInput.data(fromFile: url) }
                }
            }
            return true
        }
        _ = provider.loadDataRepresentation(forTypeIdentifier: UTType.image.identifier) { data, _ in
            Task { @MainActor in
                guard generation == model.generation else { return }
                guard let data else { model.failed(.unreadable); return }
                guard data.count <= TwoFactorQRDecoder.maxImageBytes else { model.failed(.tooLarge); return }
                read { data }
            }
        }
        return true
    }

    /// Loads and decodes off the main actor. The scan's generation is taken first, so a result that arrives
    /// after the sheet closed (or was reset) is dropped; the task is also cancelled on close.
    private func read(_ load: @escaping @Sendable () throws -> Data) {
        let generation = model.generation
        reading = true
        decoding?.cancel()
        decoding = Task {
            let result = await MacQRImageInput.decode(load)
            guard !Task.isCancelled else { return }
            reading = false
            switch result {
            case .success(let payloads): model.scanned(payloads, generation: generation)
            case .failure(let f): model.failed(f, generation: generation)
            }
        }
    }

    private func close() { decoding?.cancel(); model.reset(); onClose() }
}
