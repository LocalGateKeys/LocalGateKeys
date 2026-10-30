import SwiftUI
import UIKit
import CoreImage.CIFilterBuiltins
import AppShared

// iPhone sharing UI (UX workstream 9): Share on an item, and the Receive sheet for a `.lgkshare` file or QR.

private struct ShareInboxKey: EnvironmentKey {
    static let defaultValue: ShareInbox? = nil
}

extension EnvironmentValues {
    /// The app's inbox of received shared items (nil in previews and tests).
    var shareInbox: ShareInbox? {
        get { self[ShareInboxKey.self] }
        set { self[ShareInboxKey.self] = newValue }
    }
}

enum ShareQR {
    /// A QR image (CoreImage, low error correction so a 2 KB package still scans), each module whole pixels.
    static func image(_ text: String, correction: String = "L", side: CGFloat = 280) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = correction
        guard let output = filter.outputImage else { return nil }
        let scale = max(1, (side * 3 / output.extent.width).rounded(.down))
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg, scale: 3, orientation: .up)
    }
}

/// Share: the six-word code, the file for AirDrop / the share sheet, and the QR when the package fits.
struct ShareItemSheet: View {
    let item: VaultItem
    @Environment(\.dismiss) private var dismiss
    @State private var share: OutgoingShare?
    @State private var error: String?
    @State private var showsCodeQR = false

    var body: some View {
        NavigationStack {
            List {
                if let share {
                    Section("Code") {
                        Text(share.code)
                            .font(.system(.title2, design: .monospaced).weight(.semibold))
                            .foregroundStyle(Palette.text)
                            .textSelection(.disabled)
                            .accessibilityLabel("Code: \(share.code)")
                        Text(ShareText.codeHint).font(.footnote).foregroundStyle(Palette.secondaryText)
                        Toggle("Show the code as a QR", isOn: $showsCodeQR)
                        if showsCodeQR, let image = ShareQR.image(share.codeQRText, correction: "M") {
                            qr(image, label: String(localized: "Code QR"))
                        }
                    }
                    .listRowBackground(Palette.groupSurface)
                    Section("Send") {
                        ShareLink(item: share.fileURL) { Label("AirDrop or share the file…", systemImage: "square.and.arrow.up") }
                        if let text = share.packageQRText, let image = ShareQR.image(text) {
                            qr(image, label: String(localized: "Shared item QR"))
                            Text(ShareText.qrHint).font(.footnote).foregroundStyle(Palette.secondaryText)
                        }
                        Text(ShareText.expiresHint).font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                    .listRowBackground(Palette.groupSurface)
                } else if let error {
                    Text(error).foregroundStyle(Palette.danger).listRowBackground(Palette.groupSurface)
                } else {
                    ProgressView().listRowBackground(Color.clear)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(ShareText.shareTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .task { await prepare() }
        .onDisappear { if let share { ShareOutbox.remove(share) } }
    }

    private func qr(_ image: UIImage, label: String) -> some View {
        HStack {
            Spacer()
            Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
                .frame(maxWidth: 280).padding(12).background(Color.white)
                .accessibilityLabel(label)
            Spacer()
        }
    }

    private func prepare() async {
        guard share == nil else { return }
        let item = item
        // Argon2id takes a moment: off the main thread.
        let made = await Task.detached(priority: .userInitiated) { () -> Result<OutgoingShare, ShareError> in
            do { return .success(try ShareOutbox.make(item: item, sender: "iPhone", now: SystemClock().now)) }
            catch let e as ShareError { return .failure(e) }
            catch { return .failure(ShareError.cannotWrite) }
        }.value
        switch made {
        case .success(let s): share = s
        case .failure(let e): error = e.reason == "not-shareable" ? ShareText.cannotShare : e.message
        }
    }
}

extension ShareError {
    static let cannotWrite = ShareError("too-large", String(localized: "The shared file could not be made on this device."))
}

/// Receive: who sent it, the code (typed or scanned), the preview, then Add to vault or Reject.
struct ReceiveShareSheet: View {
    let inbox: ShareInbox
    let store: any ItemStore
    let pro: ProModel
    let onSaved: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var scanning: ScanTarget?
    @State private var opening = false

    enum ScanTarget: String, Identifiable { case package, code; var id: String { rawValue } }

    var body: some View {
        NavigationStack {
            List {
                if let message = inbox.message {
                    Text(message).foregroundStyle(inbox.preview == nil && inbox.pending == nil && message != ShareText.saved
                                                  ? Palette.danger : Palette.text)
                        .fixedSize(horizontal: false, vertical: true)
                        .listRowBackground(Palette.groupSurface)
                }
                if let preview = inbox.preview {
                    previewSection(preview)
                } else if let pending = inbox.pending {
                    Section {
                        Text(ShareText.from(pending.sender)).foregroundStyle(Palette.text)
                        TextField("Six words", text: $code, axis: .vertical)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .submitLabel(.go)
                        HStack {
                            Button("Open") { openNow() }.disabled(code.isEmpty || opening)
                            Spacer()
                            Button("Scan code QR") { scanning = .code }.buttonStyle(.borderless)
                        }
                        if opening { ProgressView() }
                    } footer: { Text(ShareText.enterCode) }
                    .listRowBackground(Palette.groupSurface)
                } else {
                    Section {
                        Button("Scan a shared item QR") { scanning = .package }
                    } footer: {
                        Text("Larger items arrive as a file: open the .lgkshare file from AirDrop or Files.")
                    }
                    .listRowBackground(Palette.groupSurface)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(ShareText.receiveTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(inbox.pending == nil ? String(localized: "Done") : String(localized: "Reject"), role: inbox.pending == nil ? nil : .destructive) {
                        inbox.reject(); dismiss()
                    }
                }
            }
            .sheet(item: $scanning) { target in
                NavigationStack {
                    QRScanner(onCode: { text in
                        scanning = nil
                        switch target {
                        case .package: inbox.deliver(text: text)
                        case .code: code = text; openNow()
                        }
                    }, onUnavailable: { scanning = nil })
                    .ignoresSafeArea()
                    .navigationTitle("Scan QR code")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanning = nil } } }
                }
            }
        }
    }

    private func previewSection(_ opened: Share.Opened) -> some View {
        let item = VaultItem(id: opened.id, record: opened.item)
        return Section {
            LabeledContent("Type", value: item?.kindLabel ?? String(localized: "Item"))
            LabeledContent("Title", value: item?.title ?? "")
            if let user = item?.username, !user.isEmpty { LabeledContent("Username", value: user) }
            if let target = item?.target, !target.isEmpty { LabeledContent("Website", value: target) }
            Button("Add to vault") {
                switch inbox.save(store: store, isPro: pro.isPro) {
                case .saved: onSaved(); dismiss()
                case .needsPro, .failed: break
                }
            }
        } header: { Text("From \(opened.sender)") }
        .listRowBackground(Palette.groupSurface)
    }

    private func openNow() {
        let text = code
        opening = true
        // The Argon2id key takes a moment; the UI stays responsive.
        Task { @MainActor in
            await Task.yield()
            inbox.open(code: text)
            opening = false
            if inbox.preview != nil { code = "" }
        }
    }
}
