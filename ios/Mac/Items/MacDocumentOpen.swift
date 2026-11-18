import AppKit
import AppSharedMac

/// Opening a document item in its default app (Windows `app/documents.py` `open_externally`, `attachments.py`
/// `write_open_copy`), with Windows' safety rules:
/// - only when Settings › Privacy › Open documents in other apps is on (on by default);
/// - only document, image, audio and video types from Windows' allow-list (`OPENABLE_SUFFIXES`), judged by the name the
///   copy gets; anything else goes through Save…, a deliberate export the person opens themselves;
/// - a one-time warning before the first decrypted copy is written;
/// - each copy sits in its own random folder (owner-only permissions) under one temporary folder, carries the quarantine
///   mark (the Mac's Mark-of-the-Web) and is refused for the macro-capable legacy Office types when the mark can't be set;
/// - every copy is deleted when the vault locks, when the app quits and at the next launch. The Mac can't tell when
///   the other app closes the file (Windows retries the delete while the file is in use), so the lock is the limit.
enum MacDocumentOpen {
    /// Windows `OPENABLE_SUFFIXES`.
    static let openableExtensions: Set<String> = [
        "pdf",
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "heif",
        "txt", "md", "csv", "json", "xml", "log",
        "docx", "xlsx", "pptx", "odt", "ods", "odp", "rtf", "epub",
        "doc", "xls", "ppt",
        "mp3", "m4a", "wav", "flac", "ogg", "aac",
        "mp4", "mov", "webm", "mkv", "avi", "m4v",
    ]
    /// Windows `MOTW_REQUIRED_SUFFIXES`: types that may carry macros open only with the quarantine mark.
    static let quarantineRequiredExtensions: Set<String> = ["doc", "xls", "ppt"]

    static let offTitle = String(localized: "Opening documents is off")
    static let offText = String(localized: "\"Open documents in other apps\" is off. Turn it on to open this file, or use Save a copy… instead.")
    static let turnOnAndOpen = String(localized: "Turn on and open")
    static let warningTitle = String(localized: "Open a decrypted copy?")
    static let warningText = String(localized: "To open this file in another app, LocalGateKeys puts a decrypted copy in a temporary folder on this Mac. It is deleted when the vault locks (and when LocalGateKeys quits or next opens). The other app may keep its own recent-files list or backups.\n\nYou won't be asked again.")
    static let notAllowedText = String(localized: "LocalGateKeys only opens documents, images, audio and video directly (for example PDF, Word, Excel, PowerPoint, text, JPG or MP4). Files of this type could run code when opened, so use Save a copy… and open the copy yourself if you trust it.")

    /// Where the copies live: `<temporary folder>/LocalGateKeys opened documents/<random>/<name>`.
    static var directory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("LocalGateKeys opened documents", isDirectory: true)
    }

    /// The name the copy gets (`AttachmentDocuments.safeFileName`, then Windows' bidi and format-character strip).
    static func copyName(_ name: String) -> String {
        let visible = String(String.UnicodeScalarView(name.unicodeScalars.filter { $0.properties.generalCategory != .format }))
        return AttachmentDocuments.safeFileName(visible)
    }

    /// True when a file of this name may go to its default app (allow-list, judged by the copy's name).
    static func canOpen(_ name: String) -> Bool {
        openableExtensions.contains((copyName(name) as NSString).pathExtension.lowercased())
    }

    /// What has to happen before a copy is written, in Windows' order: the setting, then the type, then the warning.
    enum Step: Equatable { case off, notAllowed, warn, open }

    static func nextStep(name: String, defaults: UserDefaults) -> Step {
        guard MacExtraSettings.documentOpenEnabled(defaults) else { return .off }
        guard canOpen(name) else { return .notAllowed }
        return MacExtraSettings.documentOpenWarningSeen(defaults) ? .open : .warn
    }

    enum Failure: Error, Equatable { case notAllowed, notMarked, io }

    /// Writes `data` as `name` in a fresh random folder under `root` (folder 0700, file 0600, never overwriting) and marks
    /// it as quarantined. On any failure nothing is left behind.
    static func writeCopy(_ data: Data, name: String, root: URL = directory,
                          mark: (URL) -> Bool = quarantine) throws -> URL {
        let fileName = copyName(name)
        guard canOpen(fileName) else { throw Failure.notAllowed }
        let fm = FileManager.default
        let folder = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = folder.appendingPathComponent(fileName)
        do {
            try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fm.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try data.write(to: url, options: [.withoutOverwriting])
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            try? fm.removeItem(at: folder)
            throw Failure.io
        }
        if !mark(url), quarantineRequiredExtensions.contains((fileName as NSString).pathExtension.lowercased()) {
            try? fm.removeItem(at: folder)
            throw Failure.notMarked
        }
        return url
    }

    /// The quarantine mark (`com.apple.quarantine`), so the opening app and Gatekeeper treat the copy as downloaded.
    static func quarantine(_ url: URL) -> Bool {
        var marked = url
        var values = URLResourceValues()
        values.quarantineProperties = [kLSQuarantineTypeKey as String: kLSQuarantineTypeOtherDownload,
                                       kLSQuarantineAgentNameKey as String: MacAppInfo.displayName]
        do { try marked.setResourceValues(values); return true } catch { return false }
    }

    /// Deletes every copy under `root`. A link is removed, never followed. Returns what could not be removed.
    @discardableResult
    static func sweep(_ root: URL = directory) -> [URL] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: root.path) else { return [] }
        let keys: [URLResourceKey] = [.isSymbolicLinkKey]
        var remaining: [URL] = []
        for entry in (try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: keys)) ?? [] {
            do { try fm.removeItem(at: entry) } catch { remaining.append(entry) }
        }
        if remaining.isEmpty { try? fm.removeItem(at: root) }
        return remaining
    }

    @MainActor private static var sweepsAtQuit = false

    /// At launch: removes what a crash left, and deletes the copies again when the app quits.
    @MainActor static func startSweeping() {
        sweep()
        guard !sweepsAtQuit else { return }
        sweepsAtQuit = true
        _ = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { _ in
            sweep()
        }
    }

    /// Asks the two questions Windows asks (the setting is off; the first decrypted copy), with alerts. Returns true when
    /// the copy may be written; turning the setting on or seeing the warning is saved.
    @MainActor static func confirm(name: String, defaults: UserDefaults = AppSettings.shared.defaults,
                                   onProblem: (String) -> Void) -> Bool {
        var step = nextStep(name: name, defaults: defaults)
        if step == .off {
            let alert = NSAlert()
            alert.messageText = offTitle
            alert.informativeText = offText
            alert.addButton(withTitle: turnOnAndOpen)
            alert.addButton(withTitle: String(localized: "Cancel"))
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            defaults.set(true, forKey: MacExtraSettings.documentOpenKey)
            step = nextStep(name: name, defaults: defaults)
        }
        if step == .notAllowed { onProblem(notAllowedText); return false }
        if step == .warn {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = warningTitle
            alert.informativeText = warningText
            alert.addButton(withTitle: String(localized: "Open"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            defaults.set(true, forKey: MacExtraSettings.documentOpenWarningSeenKey)
        }
        return true
    }
}
