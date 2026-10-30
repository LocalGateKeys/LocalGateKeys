import SwiftUI
import UIKit
import QuickLook
import LocalAuthentication
import UniformTypeIdentifiers
import AppShared

/// A document's file on the detail screen (task 12): name, size and type, then Preview (Quick Look), Save to
/// Files, Share and Rename (the title only). Every release of the file's content asks for Face ID, Touch ID or
/// the passcode first: an attached file is treated as sensitive. Clear copies for Preview and Share live in
/// `AttachmentFiles.openCopiesDirectory` and are deleted as soon as the preview or share sheet closes.
struct DocumentSection: View {
    let item: VaultItem
    let store: any ItemStore
    let onChange: () -> Void

    var body: some View {
        Section("File") {
            DocumentFileRow(item: item, store: store, onChange: onChange)
        }
        .listRowBackground(Palette.groupSurface)
    }
}

/// A clear temporary copy being previewed or shared.
private struct OpenCopy: Identifiable {
    let id = UUID()
    let url: URL
}

/// The file bytes handed to Save to Files (never written anywhere else by the app).
struct ExportedFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

private struct DocumentFileRow: View {
    let item: VaultItem
    let store: any ItemStore
    let onChange: () -> Void
    @State private var preview: URL?
    @State private var share: OpenCopy?
    @State private var export: ExportedFile?
    @State private var exporting = false
    @State private var renaming = false
    @State private var newTitle = ""
    @State private var problem: String?

    private var ref: AttachmentRef? { DocumentFiles.reference(id: item.id, store: store) }
    private var blobs: BlobFolder? { AttachmentFiles.localFolder() }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let ref {
                LabeledContent("File name", value: ref.name)
                LabeledContent("Size", value: DocumentFiles.sizeText(ref.size))
                if blobs?.has(ref.blob) == true {
                    HStack(spacing: 18) {
                        Button { Task { await openPreview() } } label: { Label("Preview", systemImage: "eye") }
                        Button { Task { await saveToFiles() } } label: { Label("Save", systemImage: "folder") }
                        Button { Task { await openShare() } } label: { Label("Share", systemImage: "square.and.arrow.up") }
                    }
                    .buttonStyle(.borderless)
                } else {
                    Text("The file has not arrived on this \(SyncWording.thisDevice) yet. Sync with the device that added it.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
                Button { newTitle = item.title; renaming = true } label: { Label("Rename", systemImage: "pencil") }
                    .buttonStyle(.borderless)
            } else {
                Text("This file can only be opened on the device that added it.").foregroundStyle(Palette.secondaryText)
            }
        }
        .quickLookPreview($preview)
        .onChange(of: preview) { old, new in if new == nil { DocumentFiles.removeTemporaryCopy(old) } }
        .sheet(item: $share, onDismiss: { }) { copy in
            ShareSheet(url: copy.url) { DocumentFiles.removeTemporaryCopy(copy.url) }
        }
        .fileExporter(isPresented: $exporting, document: export, contentType: .data,
                      defaultFilename: ref.map { AttachmentDocuments.safeFileName($0.name) }) { result in
            export = nil
            if case .failure = result { problem = String(localized: "The file could not be saved.") }
        }
        .alert("Rename", isPresented: $renaming) {
            TextField("Title", text: $newTitle)
            Button("Cancel", role: .cancel) {}
            Button("Save") { rename() }
        } message: {
            Text("Only the title changes; the file keeps its name.")
        }
        .alert(problem ?? "", isPresented: Binding(get: { problem != nil }, set: { if !$0 { problem = nil } })) {
            Button("OK") {}
        }
    }

    private func confirmOwner(_ reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    private func copy() -> URL? {
        do { return try DocumentFiles.temporaryCopy(id: item.id, store: store, blobs: blobs) } catch {
            problem = String(localized: "The file could not be opened. It may be damaged.")
            return nil
        }
    }

    private func openPreview() async {
        guard await confirmOwner(String(localized: "Open the attached file")) else { return }
        preview = copy()
    }

    private func openShare() async {
        guard await confirmOwner(String(localized: "Share the attached file")) else { return }
        if let url = copy() { share = OpenCopy(url: url) }
    }

    private func saveToFiles() async {
        guard await confirmOwner(String(localized: "Save the attached file")) else { return }
        do {
            export = ExportedFile(data: try DocumentFiles.contents(id: item.id, store: store, blobs: blobs).data)
            exporting = true
        } catch {
            problem = String(localized: "The file could not be opened. It may be damaged.")
        }
    }

    private func rename() {
        switch DocumentFiles.rename(id: item.id, title: newTitle, store: store, clock: SystemClock()) {
        case .saved: onChange()
        case .invalid: problem = String(localized: "Enter a title.")
        case .unchanged: break
        default: problem = String(localized: "The title could not be saved on this device.")
        }
    }
}

/// The system share sheet for one temporary copy; `done` runs when it closes (the copy is deleted then).
private struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    let done: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.completionWithItemsHandler = { _, _, _, _ in done() }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
