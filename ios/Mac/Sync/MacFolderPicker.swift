import AppKit

/// The Mac's folder picker for cloud folder sync (iPhone `FolderPicker`): an `NSOpenPanel` that chooses one
/// folder and nothing else. The sandbox grants access to the chosen URL; the caller turns it into an
/// app-scoped, security-scoped bookmark at once (`SecurityScopedFolderOpener.bookmark(for:)`).
@MainActor
enum MacFolderPicker {
    static let message = String(localized: "Choose a folder your cloud app syncs, such as iCloud Drive.")

    /// The chosen folder, or nil when the person cancelled.
    static func choose() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.message = message
        panel.prompt = String(localized: "Choose")
        return panel.runModal() == .OK ? panel.url : nil
    }
}
