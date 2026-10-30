import SwiftUI
import UIKit
import PhotosUI
import UniformTypeIdentifiers
import AppShared

/// "Attach a file" (task 12): Files, Photos or the camera, then one new document item. Pro only, 25 MB per file.
/// The chosen bytes are sealed at once (`DocumentFiles.add`); no clear copy is kept.
struct AddFileFlow: ViewModifier {
    @Binding var isPresented: Bool
    let store: any ItemStore
    let pro: ProModel
    let onNeedsPro: () -> Void
    let onAdded: () -> Void
    @State private var importing = false
    @State private var pickingPhoto = false
    @State private var photo: PhotosPickerItem?
    @State private var camera = false
    @State private var problem: String?

    func body(content: Content) -> some View {
        content
            .confirmationDialog("Attach a file", isPresented: $isPresented, titleVisibility: .visible) {
                Button("Choose from Files") { importing = true }
                Button("Photo Library") { pickingPhoto = true }
                if UIImagePickerController.isSourceTypeAvailable(.camera) {
                    Button("Take Photo") { camera = true }
                }
            } message: {
                Text("The file is stored encrypted in your vault and syncs to your other devices. Up to 25 MB.")
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
                guard case .success(let url) = result else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > DocumentFiles.maxBytes {
                    problem = DocumentFiles.tooLargeMessage; return
                }
                guard let data = try? Data(contentsOf: url) else { problem = String(localized: "The file could not be read."); return }
                save(data, name: url.lastPathComponent)
            }
            .photosPicker(isPresented: $pickingPhoto, selection: $photo, matching: .images)
            .onChange(of: photo) { _, item in
                guard let item else { return }
                photo = nil
                Task { @MainActor in
                    guard let data = try? await item.loadTransferable(type: Data.self) else { problem = String(localized: "The photo could not be read."); return }
                    let ext = item.supportedContentTypes.first?.preferredFilenameExtension ?? "jpg"
                    save(data, name: "Photo \(Self.stamp()).\(ext)")
                }
            }
            .fullScreenCover(isPresented: $camera) {
                CameraPicker { data in
                    camera = false
                    if let data { save(data, name: "Photo \(Self.stamp()).jpg") }
                }
                .ignoresSafeArea()
            }
            .alert(problem ?? "", isPresented: Binding(get: { problem != nil }, set: { if !$0 { problem = nil } })) {
                Button("OK") {}
            }
    }

    static func stamp() -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return f.string(from: Date())
    }

    @MainActor
    private func save(_ data: Data, name: String) {
        if let snap = try? store.load(), !ItemLimit.allows(.create, snapshot: snap, isPro: pro.isPro) { onNeedsPro(); return }
        switch DocumentFiles.add(data: data, fileName: name, isPro: pro.isPro, store: store, blobs: AttachmentFiles.localFolder(),
                                 clock: SystemClock(), random: SystemRandomSource()) {
        case .saved: onAdded()
        case .needsPro: onNeedsPro()
        case .tooLarge: problem = DocumentFiles.tooLargeMessage
        case .unavailable, .failed: problem = String(localized: "The file could not be saved on this iPhone.")
        }
    }
}

/// The camera, returning a JPEG (nil when cancelled).
private struct CameraPicker: UIViewControllerRepresentable {
    let done: (Data?) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(done: done) }

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIImagePickerController, context: Context) {}

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let done: (Data?) -> Void
        init(done: @escaping (Data?) -> Void) { self.done = done }

        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
            let image = info[.originalImage] as? UIImage
            done(image?.jpegData(compressionQuality: 0.85))
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) { done(nil) }
    }
}
