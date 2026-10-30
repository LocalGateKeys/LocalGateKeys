import SwiftUI
import AppKit
import UniformTypeIdentifiers
import AppSharedMac

// Mac sharing UI (UX workstream 9): Share on an item (AirDrop / share menu / Save…, QR when it fits) and the
// Receive sheet for a `.lgkshare` file opened from Finder or AirDrop.

enum MacShareText {
    static var senderName: String { Host.current().localizedName.map { String($0.prefix(Share.senderLimit)) } ?? "Mac" }
}

/// Share: the six-word code, the file and the QR when the package is small enough.
struct MacShareSheet: View {
    let item: VaultItem
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var share: OutgoingShare?
    @State private var error: String?
    @State private var saving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(ShareText.shareTitle).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
            if let share {
                Text(share.code)
                    .font(.system(size: 22, weight: .semibold, design: .monospaced))
                    .foregroundStyle(theme.text)
                    .accessibilityLabel("Code: \(share.code)")
                Text(ShareText.codeHint).font(.callout).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let text = share.packageQRText, let image = SyncPageModel.qrImage(text, side: 240) {
                    HStack {
                        Spacer()
                        Image(nsImage: image).interpolation(.none).accessibilityLabel("Shared item QR")
                        Spacer()
                    }
                    Text(ShareText.qrHint).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                }
                Text(ShareText.expiresHint).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                HStack(spacing: 8) {
                    ShareLink(item: share.fileURL) { Text("AirDrop or share…") }
                        .buttonStyle(PillButtonStyle(primary: true))
                    Button("Save file…") { saving = true }
                        .buttonStyle(PillButtonStyle(primary: false))
                    Spacer()
                    Button("Done", action: onClose).buttonStyle(PillButtonStyle(primary: false))
                        .keyboardShortcut(.cancelAction)
                }
            } else if let error {
                MessageLine(text: error)
                HStack { Spacer(); Button("Close", action: onClose).buttonStyle(PillButtonStyle(primary: false)) }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .padding(22)
        .frame(width: 440)
        .task { await prepare() }
        .onDisappear { if let share { ShareOutbox.remove(share) } }
        .fileExporter(isPresented: $saving, document: share.map { ShareFileDocument(url: $0.fileURL) },
                      contentType: ShareFileDocument.type, defaultFilename: ShareOutbox.fileName) { _ in }
    }

    private func prepare() async {
        guard share == nil else { return }
        let item = item, sender = MacShareText.senderName
        let made = await Task.detached(priority: .userInitiated) { () -> Result<OutgoingShare, ShareError> in
            do { return .success(try ShareOutbox.make(item: item, sender: sender, now: SystemClock().now)) }
            catch let e as ShareError { return .failure(e) }
            catch { return .failure(ShareError("too-large", String(localized: "The shared file could not be made on this Mac."))) }
        }.value
        switch made {
        case .success(let s): share = s
        case .failure(let e): error = e.reason == "not-shareable" ? ShareText.cannotShare : e.message
        }
    }
}

/// The sealed package as a document for Save… (read once from the temporary file).
struct ShareFileDocument: FileDocument {
    static let type = UTType(exportedAs: "app.localgatekeys.lgkshare", conformingTo: .data)
    static var readableContentTypes: [UTType] { [type] }
    let data: Data

    init(url: URL) { data = (try? Data(contentsOf: url)) ?? Data() }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

/// Receive: the sender, the six words, the preview, then Add to vault or Reject.
struct MacReceiveShareSheet: View {
    let inbox: ShareInbox
    let store: any ItemStore
    let pro: ProModel
    let onSaved: () -> Void
    let onNeedsPro: () -> Void
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var code = ""
    @State private var opening = false
    @State private var pasted = ""
    @State private var choosingFile = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(ShareText.receiveTitle).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
            if let message = inbox.message { MessageLine(text: message) }
            if let opened = inbox.preview {
                let item = VaultItem(id: opened.id, record: opened.item)
                Text("From \(opened.sender)").font(.callout).foregroundStyle(theme.textMuted)
                VStack(alignment: .leading, spacing: 4) {
                    Text(item?.kindLabel ?? String(localized: "Item")).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    Text(item?.title ?? "").font(.system(size: 15, weight: .semibold))
                    if let user = item?.username, !user.isEmpty { Text(user).font(.system(size: 13)) }
                    if let target = item?.target, !target.isEmpty { Text(target).font(.system(size: 13)).foregroundStyle(theme.textMuted) }
                }
                HStack {
                    Button("Reject") { inbox.reject(); onClose() }.buttonStyle(PillButtonStyle(primary: false))
                    Spacer()
                    Button("Add to vault") {
                        switch inbox.save(store: store, isPro: pro.isPro) {
                        case .saved: onSaved(); onClose()
                        case .needsPro: onNeedsPro()
                        case .failed: break
                        }
                    }
                    .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                }
            } else if let pending = inbox.pending {
                Text(ShareText.from(pending.sender)).font(.callout).foregroundStyle(theme.text)
                TextField("Six words", text: $code).glassField().onSubmit(openNow)
                Text(ShareText.enterCode).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                HStack {
                    Button("Reject") { inbox.reject(); onClose() }.buttonStyle(PillButtonStyle(primary: false))
                    Spacer()
                    if opening { ProgressView().controlSize(.small) }
                    Button("Open", action: openNow).buttonStyle(PillButtonStyle(primary: true))
                        .disabled(code.isEmpty || opening).keyboardShortcut(.defaultAction)
                }
            } else {
                Text("Open the .lgkshare file you received (or drop it here), or paste the text of its QR code.")
                    .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                TextField("QR text", text: $pasted, axis: .vertical)
                    .lineLimit(2...4).font(.system(size: 12, design: .monospaced)).glassField()
                HStack {
                    Button("Open a file…") { choosingFile = true }.buttonStyle(PillButtonStyle(primary: false))
                    Spacer()
                    Button("Close") { inbox.clearMessage(); onClose() }.buttonStyle(PillButtonStyle(primary: false))
                    Button("Continue") { inbox.deliver(text: pasted); pasted = "" }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .padding(22)
        .frame(width: 420)
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [ShareFileDocument.type]) { result in
            if case .success(let url) = result { inbox.deliver(fileURL: url) }
        }
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            guard inbox.pending == nil, let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in inbox.deliver(fileURL: url) }
            }
            return true
        }
    }

    private func openNow() {
        let text = code
        opening = true
        Task { @MainActor in
            await Task.yield()
            inbox.open(code: text)
            opening = false
            if inbox.preview != nil { code = "" }
        }
    }
}
