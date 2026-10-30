import SwiftUI
import AppKit
import QuickLook
import UniformTypeIdentifiers
import AppSharedMac

/// A document's file in the detail panel (task 12): name and size, then Quick Look, Save…, and Rename (title
/// only). Opening or saving the file goes through the gate first (Touch ID or the master password, as for any
/// routine secret). The clear Quick Look copy is deleted when the preview closes.
struct DocumentFileSection: View {
    let item: VaultItem
    let store: any ItemStore
    let gate: StrictItemGate
    let onChanged: () -> Void
    @State private var preview: URL?
    @State private var renaming = false
    @State private var newTitle = ""
    @State private var problem: String?
    @Environment(\.macTheme) private var theme

    private var ref: AttachmentRef? { DocumentFiles.reference(id: item.id, store: store) }
    private var blobs: BlobFolder? { AttachmentFiles.localFolder() }

    var body: some View {
        SectionLabel(String(localized: "File"))
        if let ref {
            KeyValueRow(label: String(localized: "File name")) { Text(ref.name).textSelection(.enabled) } actions: { EmptyView() }
            KeyValueRow(label: String(localized: "Size")) { Text(DocumentFiles.sizeText(ref.size)) } actions: { EmptyView() }
            HStack(spacing: 10) {
                if blobs?.has(ref.blob) == true {
                    Button("Quick Look") { gate.releaseRoutine(item, action: String(localized: "Open the attached file")) { openPreview() } }
                        .buttonStyle(PillButtonStyle(primary: true))
                    Button("Save…") { gate.releaseRoutine(item, action: String(localized: "Save the attached file")) { save(ref) } }
                        .buttonStyle(PillButtonStyle(primary: false))
                } else {
                    Text("The file has not arrived on this Mac yet. Sync with the device that added it.")
                        .foregroundStyle(theme.textMuted)
                }
                Button("Rename…") { newTitle = item.title; renaming = true }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
            .padding(.vertical, 6)
            .quickLookPreview($preview)
            .onChange(of: preview) { old, new in if new == nil { DocumentFiles.removeTemporaryCopy(old) } }
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
        } else {
            Text("This file can only be opened on the device that added it.").foregroundStyle(theme.textMuted).padding(.vertical, 6)
        }
    }

    private func openPreview() {
        do { preview = try DocumentFiles.temporaryCopy(id: item.id, store: store, blobs: blobs) } catch {
            problem = String(localized: "The file could not be opened. It may be damaged.")
        }
    }

    /// Writes the clear file only where the person chose, through the save panel.
    private func save(_ ref: AttachmentRef) {
        let data: Data
        do { data = try DocumentFiles.contents(id: item.id, store: store, blobs: blobs).data } catch {
            problem = String(localized: "The file could not be opened. It may be damaged."); return
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = AttachmentDocuments.safeFileName(ref.name)
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try data.write(to: url, options: .atomic) } catch { problem = String(localized: "The file could not be saved.") }
    }

    private func rename() {
        switch DocumentFiles.rename(id: item.id, title: newTitle, store: store, clock: SystemClock()) {
        case .saved: onChanged()
        case .invalid: problem = String(localized: "Enter a title.")
        case .unchanged: break
        default: problem = String(localized: "The title could not be saved on this Mac.")
        }
    }
}

enum MacAttachFile {
    /// "Attach a file…": an open panel, then one new document item (Pro, 25 MB).
    @MainActor
    static func run(store: any ItemStore, isPro: Bool) -> DocumentFiles.AddResult? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = String(localized: "The file is stored encrypted in your vault and syncs to your other devices. Up to 25 MB.")
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > DocumentFiles.maxBytes { return .tooLarge }
        guard let data = try? Data(contentsOf: url) else { return .failed }
        return DocumentFiles.add(data: data, fileName: url.lastPathComponent, isPro: isPro, store: store,
                                 blobs: AttachmentFiles.localFolder(), clock: SystemClock(), random: SystemRandomSource())
    }
}
