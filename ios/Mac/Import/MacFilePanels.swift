import AppKit
import UniformTypeIdentifiers

/// The Import & export page's file panels (the app is sandboxed: the panels grant access to the chosen file).
@MainActor
enum MacFilePanels {
    static let importMessage = String(localized: "Choose an export from another password manager, or a CSV file.")
    static let restoreMessage = String(localized: "Choose a phone backup (.lgkm).")

    /// The file to import, or nil when the person cancelled. Any file can be chosen: the format is detected.
    static func chooseImport() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.message = importMessage
        panel.prompt = String(localized: "Import")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// The phone backup to restore, or nil.
    static func chooseBackup() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let lgkm = UTType(filenameExtension: "lgkm") { panel.allowedContentTypes = [lgkm] }
        panel.message = restoreMessage
        panel.prompt = String(localized: "Restore")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Where to write an export, or nil. The extension is kept (`.csv` / `.lgkm`).
    static func chooseExport(name: String, csv: Bool) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        if csv { panel.allowedContentTypes = [.commaSeparatedText] }
        else if let lgkm = UTType(filenameExtension: "lgkm") { panel.allowedContentTypes = [lgkm] }
        panel.message = csv ? String(localized: "The CSV file is not encrypted. Save it somewhere only you can read, and delete it after importing.")
            : String(localized: "Save the encrypted backup.")
        panel.prompt = String(localized: "Export")
        return panel.runModal() == .OK ? panel.url : nil
    }
}
