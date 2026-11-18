import SwiftUI
import AppKit
import Observation
import CryptoKit
import LGKCore
import AppSharedMac

// Port of the Windows `secret_scan.py` and the import half of `secret_scan_service.py`: finds plain SSH private keys
// (in `.ssh` folders) and `.env` files under a folder the user picks, and imports them into the vault. It only reads
// files: never follows symbolic links, skips files over 1 MiB, `Library`, `node_modules`, `.git`, `venv`/`.venv`,
// `AppData` and every hidden folder except `.ssh`, goes 4 folders deep, and never shows a value (a path, a kind and a
// variable count only). Import copies into the vault and never changes, moves or deletes the file.
//
// The Windows "Use references" (rewrite a `.env` to `lgk://` references) is not on the Mac: the `lgk` command that
// reads them does not exist on the Mac yet (docs/superpowers/specs/2026-11-03-feature-pack-design.md §3.4).

enum SecretScanner {
    static let maxFileBytes = 1024 * 1024
    static let maxDepth = 4
    static let skipDirs: Set<String> = ["appdata", "node_modules", ".git", "venv", ".venv", "library"]
    /// Template files hold no real secrets.
    static let templateSuffixes: Set<String> = ["example", "sample", "template", "dist", "defaults"]
    static let headerBytes = 512

    enum Kind: String, Sendable { case sshPrivateKey = "ssh_private_key", envFile = "env_file" }

    struct Finding: Equatable, Sendable, Identifiable {
        let url: URL
        let kind: Kind
        var varCount = 0
        var keyFormat: String?
        var id: String { url.path }
    }

    static func isEnvName(_ name: String) -> Bool {
        let lowered = name.lowercased()
        if lowered == ".env" { return true }
        guard lowered.hasPrefix(".env.") else { return false }
        return !templateSuffixes.contains(String(lowered.split(separator: ".", omittingEmptySubsequences: false).last ?? ""))
    }

    /// Findings under `root`, sorted by path; stops early (with what it has) when `isCancelled` turns true.
    static func scan(root: URL, maxDepth: Int = SecretScanner.maxDepth, isCancelled: () -> Bool = { false }) -> [Finding] {
        guard !isLink(root), isDirectory(root) else { return [] }
        var found: [String: Finding] = [:]
        var stack: [(URL, Int, Bool)] = [(root, 0, false)]
        let keys: [URLResourceKey] = [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey]
        while let next = stack.popLast(), !isCancelled() {
            let (folder, depth, inSSH) = next
            guard let entries = try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: keys) else { continue }
            for entry in entries {
                if isCancelled() { break }
                guard let values = try? entry.resourceValues(forKeys: Set(keys)), values.isSymbolicLink != true else { continue }
                let name = entry.lastPathComponent
                if values.isDirectory == true {
                    let lowered = name.lowercased()
                    let ssh = lowered == ".ssh"
                    if depth < maxDepth && !skipDirs.contains(lowered) && (ssh || !lowered.hasPrefix(".")) {
                        stack.append((entry, depth + 1, ssh))
                    }
                } else if values.isRegularFile == true {
                    guard isEnvName(name) || (inSSH && !name.lowercased().hasSuffix(".pub")) else { continue }
                    if let finding = describe(entry) { found[entry.path] = found[entry.path] ?? finding }
                }
            }
        }
        return found.values.sorted { $0.url.path.lowercased() < $1.url.path.lowercased() }
    }

    /// The finding for one file, or nil when it holds no plain secret.
    static func describe(_ url: URL) -> Finding? {
        guard regularFile(url) else { return nil }
        let name = url.lastPathComponent
        if isEnvName(name) {
            let count = readText(url).map(EnvFile.plainVariableCount) ?? 0
            return count > 0 ? Finding(url: url, kind: .envFile, varCount: count) : nil
        }
        guard url.deletingLastPathComponent().lastPathComponent.lowercased() == ".ssh", !name.lowercased().hasSuffix(".pub"),
              let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let head = String(decoding: (try? handle.read(upToCount: headerBytes)) ?? Data(), as: UTF8.self)
        let format = Normalise.keyFormat(head)
        return format.isEmpty || format == "unknown" ? nil : Finding(url: url, kind: .sshPrivateKey, keyFormat: format)
    }

    /// A plain file of at most 1 MiB (the link itself is looked at, never its target).
    static func regularFile(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.intValue else { return false }
        return size <= maxFileBytes
    }

    /// The file as UTF-8 text (a leading BOM dropped), or nil when it is too big or not UTF-8.
    static func readText(_ url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var data = (try? handle.read(upToCount: maxFileBytes + 1)) ?? Data()
        guard data.count <= maxFileBytes else { return nil }
        if data.starts(with: [0xEF, 0xBB, 0xBF]) { data = data.dropFirst(3) }
        return String(data: Data(data), encoding: .utf8)
    }

    static func isLink(_ url: URL) -> Bool {
        (try? FileManager.default.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType == .typeSymbolicLink
    }

    static func isDirectory(_ url: URL) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) && isDir.boolValue
    }
}

/// Windows `parse_env` / `plain_variable_count` / `referenceable`, on Unicode scalars so indices match Python's.
enum EnvFile {
    struct Line: Equatable {
        let raw: String
        var key: String?
        var value: String?
        var trailing = false
        var quote: Unicode.Scalar?

        /// A double-quoted value with a backslash: dotenv expands escapes, a stored raw copy would differ.
        var escaped: Bool { quote == "\"" && (value?.contains("\\") ?? false) }
    }

    static let maxFields = 50
    static let maxFieldValue = 4096
    static let maxFieldName = 100

    static func isBlank(_ c: Unicode.Scalar) -> Bool { c == " " || c == "\t" }

    static func string(_ scalars: some Sequence<Unicode.Scalar>) -> String {
        var view = String.UnicodeScalarView()
        view.append(contentsOf: scalars)
        return String(view)
    }

    /// `re.findall(r"[^\n]*\n|[^\n]+", text)`: every line with its "\n".
    static func splitLines(_ text: [Unicode.Scalar]) -> [[Unicode.Scalar]] {
        var lines: [[Unicode.Scalar]] = []
        var current: [Unicode.Scalar] = []
        for c in text {
            current.append(c)
            if c == "\n" { lines.append(current); current = [] }
        }
        if !current.isEmpty { lines.append(current) }
        return lines
    }

    /// `raw.rstrip("\r\n")`.
    static func stripNewlines(_ s: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var end = s.count
        while end > 0 && (s[end - 1] == "\n" || s[end - 1] == "\r") { end -= 1 }
        return Array(s[..<end])
    }

    /// `_ASSIGN`: `^([ \t]*)(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*`; (key, end of the match).
    static func matchAssign(_ s: [Unicode.Scalar]) -> (key: String, end: Int)? {
        var i = 0
        while i < s.count && isBlank(s[i]) { i += 1 }
        let export = Array("export".unicodeScalars)
        if s.count - i > export.count, Array(s[i..<i + export.count]) == export, isBlank(s[i + export.count]) {
            var j = i + export.count
            while j < s.count && isBlank(s[j]) { j += 1 }
            if let match = keyAndEquals(s, from: j) { return match }
        }
        return keyAndEquals(s, from: i)
    }

    private static func keyAndEquals(_ s: [Unicode.Scalar], from start: Int) -> (key: String, end: Int)? {
        func first(_ c: Unicode.Scalar) -> Bool { ("A"..."Z").contains(c) || ("a"..."z").contains(c) || c == "_" }
        func rest(_ c: Unicode.Scalar) -> Bool { first(c) || ("0"..."9").contains(c) || c == "." || c == "-" }
        guard start < s.count, first(s[start]) else { return nil }
        var i = start + 1
        while i < s.count && rest(s[i]) { i += 1 }
        let key = string(s[start..<i])
        while i < s.count && isBlank(s[i]) { i += 1 }
        guard i < s.count, s[i] == "=" else { return nil }
        i += 1
        while i < s.count && isBlank(s[i]) { i += 1 }
        return (key, i)
    }

    /// `_end_of_quote`: the closing quote after `start`, or nil; a double quote honours backslash escapes.
    static func endOfQuote(_ s: [Unicode.Scalar], from start: Int, quote: Unicode.Scalar) -> Int? {
        var i = start
        while i < s.count {
            if s[i] == "\\" && quote == "\"" { i += 2; continue }
            if s[i] == quote { return i }
            i += 1
        }
        return nil
    }

    static func parse(_ text: String) -> [Line] {
        let lines = splitLines(Array(text.unicodeScalars))
        var result: [Line] = []
        var index = 0
        while index < lines.count {
            var raw = lines[index]
            index += 1
            var body = stripNewlines(raw)
            if body.drop(while: { $0.properties.isWhitespace }).first == "#" {
                result.append(Line(raw: string(raw)))
                continue
            }
            guard let match = matchAssign(body) else {
                result.append(Line(raw: string(raw)))
                continue
            }
            let key = match.key, start = match.end
            let quote: Unicode.Scalar? = start < body.count && (body[start] == "\"" || body[start] == "'") ? body[start] : nil
            if let quote {
                var closing = endOfQuote(body, from: start + 1, quote: quote)
                while closing == nil && index < lines.count {   // a multi-line quoted value
                    raw += lines[index]
                    index += 1
                    body = stripNewlines(raw)
                    closing = endOfQuote(body, from: start + 1, quote: quote)
                }
                guard let closing else {   // never closed: the rest stays plain text
                    result.append(Line(raw: string(raw)))
                    continue
                }
                let rest = body[(closing + 1)...]
                result.append(Line(raw: string(raw), key: key, value: string(body[(start + 1)..<closing]),
                                   trailing: rest.contains { !$0.properties.isWhitespace }, quote: quote))
                continue
            }
            if start < body.count, body[start] == "#", isBlank(body[start - 1]) {   // KEY= #note: an empty value
                result.append(Line(raw: string(raw), key: key, value: "", trailing: true))
                continue
            }
            // Unquoted: the value ends at the first " #" (a comment) or at the end of the line.
            var end = body.count
            var comment = false
            var i = start
            while i + 1 < body.count {
                if isBlank(body[i]) && body[i + 1] == "#" { end = i; comment = true; break }
                i += 1
            }
            var valueEnd = end
            while valueEnd > start && isBlank(body[valueEnd - 1]) { valueEnd -= 1 }
            result.append(Line(raw: string(raw), key: key, value: string(body[start..<valueEnd]), trailing: comment))
        }
        return result
    }

    /// Variables with a value that is not already an `lgk://` reference.
    static func plainVariableCount(_ text: String) -> Int {
        parse(text).filter { line in
            guard line.key != nil, let value = line.value, !value.isEmpty else { return false }
            return !value.hasPrefix("lgk://")
        }.count
    }

    /// name -> value of the variables a note field can hold (the last assignment of a name wins), in first-seen
    /// order: no empty values, references, inline comments, escaped double-quoted values, too-long names or values,
    /// and at most 50.
    static func referenceable(_ text: String) -> [(name: String, value: String)] {
        var order: [String] = []
        var last: [String: String] = [:]
        var blocked: Set<String> = []
        for line in parse(text) {
            guard let key = line.key, let value = line.value, !value.isEmpty, !value.hasPrefix("lgk://") else { continue }
            if line.trailing || line.escaped { blocked.insert(key) }
            if last[key] == nil { order.append(key) }
            last[key] = value
        }
        let names = order.filter { name in
            !blocked.contains(name) && last[name]!.unicodeScalars.count <= maxFieldValue && name.unicodeScalars.count <= maxFieldName
        }
        return names.prefix(maxFields).map { (name: $0, value: last[$0]!) }
    }
}

// MARK: - The scan page

/// Developer › Scan for plain secrets: the folder, the scan, the list and Import.
@MainActor @Observable
final class SecretScanModel {
    static let folderKey = "settings.mac.developer.scanFolder"

    private(set) var findings: [SecretScanner.Finding] = []
    /// Finding id -> item id, for this unlock session (a re-scan keeps what this very file became).
    private(set) var imported: [String: String] = [:]
    var selected: Set<String> = []
    private(set) var scanning = false
    private(set) var message: String?
    private(set) var folderPath: String?

    @ObservationIgnored private let store: () -> (any ItemStore)?
    @ObservationIgnored private let isPro: () -> Bool
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let bookmarks: any BookmarkResolving
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let random: any RandomSource
    /// (path, SHA-256 of the file as imported) -> item id: the same file is never imported twice.
    @ObservationIgnored private var marks: [String: String] = [:]
    @ObservationIgnored private var scanTask: Task<Void, Never>?
    @ObservationIgnored private var scanStop: ScanStop?
    @ObservationIgnored var onNeedsPro: () -> Void = {}

    init(store: @escaping () -> (any ItemStore)?, isPro: @escaping () -> Bool, defaults: UserDefaults = .standard,
         bookmarks: any BookmarkResolving = SecurityScopedBookmarks(), clock: any UnixClock = SystemClock(),
         random: any RandomSource = SystemRandomSource()) {
        self.store = store; self.isPro = isPro; self.defaults = defaults; self.bookmarks = bookmarks
        self.clock = clock; self.random = random
        folderPath = (try? resolvedFolder())?.path
    }

    private func resolvedFolder() throws -> URL? {
        guard let data = defaults.data(forKey: Self.folderKey) else { return nil }
        let (url, refreshed) = try bookmarks.resolve(Array(data))
        if let refreshed { defaults.set(Data(refreshed), forKey: Self.folderKey) }
        return url
    }

    /// The open panel (the user's home folder first, hidden folders shown so `.ssh` can be picked).
    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.message = String(localized: "secret_scan.chooseFolder", defaultValue: "Choose a folder to scan")
        panel.prompt = String(localized: "secret_scan.scan", defaultValue: "Scan")
        if let home = getpwuid(getuid())?.pointee.pw_dir { panel.directoryURL = URL(fileURLWithPath: String(cString: home)) }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        setFolder(url)
        scan()
    }

    func setFolder(_ url: URL) {
        guard let bytes = try? bookmarks.bookmark(for: url) else {
            message = String(localized: "secret_scan.err.folders", defaultValue: "Choose folders that exist."); return
        }
        defaults.set(Data(bytes), forKey: Self.folderKey)
        folderPath = url.path
    }

    /// Starts a scan of the chosen folder; the task ends once the list is shown (tests wait for it).
    @discardableResult
    func scan() -> Task<Void, Never>? {
        guard !scanning else { return nil }
        guard store() != nil else { message = MacSettingsModel.lockedMessage; return nil }
        guard let folder = try? resolvedFolder() else {
            message = String(localized: "secret_scan.err.folders", defaultValue: "Choose folders that exist."); return nil
        }
        scanning = true
        message = String(localized: "secret_scan.starting", defaultValue: "Scanning…")
        let stop = ScanStop()
        scanStop = stop
        scanTask = Task { [weak self] in
            let (found, keys) = await Task.detached(priority: .userInitiated) { () -> ([SecretScanner.Finding], [String: String]) in
                let scoped = folder.startAccessingSecurityScopedResource()
                defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
                let results = SecretScanner.scan(root: folder, isCancelled: { stop.isSet })
                // The import marks read the files too, so inside the folder's grant.
                var marks: [String: String] = [:]
                for finding in results { if let key = SecretScanModel.mark(finding) { marks[finding.id] = key } }
                return (results, marks)
            }.value
            self?.finish(found, marks: keys)
        }
        return scanTask
    }

    func cancel() {
        scanStop?.set()
        scanStop = nil
        scanTask?.cancel()
        scanTask = nil
        scanning = false
        message = String(localized: "secret_scan.cancelled", defaultValue: "The scan was stopped.")
    }

    private func finish(_ found: [SecretScanner.Finding], marks keys: [String: String]) {
        guard scanning, store() != nil else { scanning = false; return }   // cancelled, or locked meanwhile
        scanning = false
        findings = found
        imported = [:]
        for finding in found { if let key = keys[finding.id], let id = marks[key] { imported[finding.id] = id } }
        selected = Set(found.map(\.id)).subtracting(imported.keys)
        message = found.isEmpty ? String(localized: "secret_scan.none", defaultValue: "No plain secrets found.")
            : String(localized: "secret_scan.done", defaultValue: "Plain secrets found: \(found.count).")
    }

    /// Locking forgets the results and what was imported.
    func reset() {
        scanStop?.set(); scanStop = nil
        scanTask?.cancel(); scanTask = nil
        scanning = false; findings = []; imported = [:]; marks = [:]; selected = []; message = nil
    }

    /// "path NUL SHA-256 of the file": the same file, unchanged, is the same mark.
    nonisolated static func mark(_ finding: SecretScanner.Finding) -> String? {
        guard let data = try? Data(contentsOf: finding.url) else { return nil }
        return finding.url.path + "\u{0}" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: import

    /// Copies the selected findings into the vault (a key becomes an SSH key item, a `.env` a note titled
    /// `<folder>/.env` with one hidden field per variable). The files are never changed.
    func importSelected() {
        guard let store = self.store() else { message = MacSettingsModel.lockedMessage; return }
        guard let folder = try? resolvedFolder() else { return }
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        var done = 0
        var failures: [String] = []
        for finding in findings where selected.contains(finding.id) && imported[finding.id] == nil {
            let key = Self.mark(finding)
            if let key, let id = marks[key] { imported[finding.id] = id; continue }
            do {
                var snap = try store.load()
                guard ItemLimit.allows(.create, snapshot: snap, isPro: isPro()) else {
                    failures.append(String(localized: "secret_scan.limit", defaultValue: "The free plan holds \(ItemLimit.freeItems) items. Pro unlocks unlimited items."))
                    onNeedsPro()
                    break
                }
                var newID = ImportReviewModel.put(try record(for: finding), ns: .item, into: &snap, isNew: true)
                if newID == nil, let fallback = fallbackRecord(for: finding) {
                    newID = ImportReviewModel.put(fallback, ns: .item, into: &snap, isNew: true)
                }
                guard let id = newID else {
                    failures.append("\(finding.url.lastPathComponent): \(String(localized: "secret_scan.err.importOne", defaultValue: "It could not be imported."))")
                    continue
                }
                try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
                imported[finding.id] = id
                if let key { marks[key] = id }
                done += 1
            } catch ImportFailure.tooLong {
                failures.append("\(finding.url.lastPathComponent): \(String(localized: "secret_scan.err.tooLong", defaultValue: "This file is too long for a note (more than \(Self.maxNote) characters)."))")
            } catch {
                failures.append("\(finding.url.lastPathComponent): \(String(localized: "secret_scan.err.importOne", defaultValue: "It could not be imported."))")
            }
        }
        selected.subtract(imported.keys)
        message = ([String(localized: "secret_scan.imported", defaultValue: "Imported: \(done).")] + failures).joined(separator: " ")
    }

    enum ImportFailure: Error { case unreadable, tooLong }

    static let maxNote = 20_000

    private func newRecord(kind: String, title: String, payload: [String: JSONValue]) -> [String: JSONValue] {
        let now = clock.now
        return ["id": .string(EditorModel.uuid4(random)), "kind": .string(kind), "title": .string(title),
                "payload": .object(payload), "created_at": .int(now), "updated_at": .int(now),
                "favorite": .bool(false), "tags": .array([])]
    }

    /// The new item's record (Windows `_import_ssh` / `_import_env`).
    private func record(for finding: SecretScanner.Finding) throws -> [String: JSONValue] {
        guard SecretScanner.regularFile(finding.url), let text = SecretScanner.readText(finding.url) else { throw ImportFailure.unreadable }
        let name = finding.url.lastPathComponent
        switch finding.kind {
        case .sshPrivateKey:
            var publicLine = "", fingerprint = ""
            if let key = try? SSHKey.load(text, passphrase: nil) {   // encrypted or another format: stored without a public half
                publicLine = key.publicLine(comment: name)
                fingerprint = key.fingerprint
            }
            return newRecord(kind: "ssh_key", title: name, payload: ["private_key": .string(text), "public_key": .string(publicLine),
                                                                     "fingerprint": .string(fingerprint)])
        case .envFile:
            guard text.unicodeScalars.count <= Self.maxNote else { throw ImportFailure.tooLong }
            // One hidden field per variable, as Windows stores it (lgk://<id>/<NAME> resolves there).
            let fields = EnvFile.referenceable(text).map { JSONValue.object(["name": .string($0.name), "value": .string($0.value),
                                                                              "hidden": .bool(true)]) }
            return newRecord(kind: "note", title: envTitle(finding), payload: ["body": .string(text), "fields": .array(fields)])
        }
    }

    /// A `.env` whose variables the vault refuses as fields (a control character, say) is kept as text only.
    private func fallbackRecord(for finding: SecretScanner.Finding) -> [String: JSONValue]? {
        guard finding.kind == .envFile, let text = SecretScanner.readText(finding.url) else { return nil }
        return newRecord(kind: "note", title: envTitle(finding), payload: ["body": .string(text), "fields": .array([])])
    }

    func envTitle(_ finding: SecretScanner.Finding) -> String {
        let parent = finding.url.deletingLastPathComponent().lastPathComponent
        return "\(parent.isEmpty ? "env" : parent)/\(finding.url.lastPathComponent)"
    }
}

/// Stops a running scan from the main actor; read by the scan's thread.
final class ScanStop: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    func set() {
        lock.lock()
        stopped = true
        lock.unlock()
    }
}

/// The scan sheet (Settings › Developer › Scan…).
struct SecretScanSheet: View {
    @Bindable var model: SecretScanModel
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "secret_scan.title.mac", defaultValue: "Plain secrets on this Mac"))
                .font(.system(size: 15, weight: .semibold))
            Text(String(localized: "secret_scan.intro.mac", defaultValue: "Looks for SSH private keys in .ssh folders and for .env files in the folder you choose. It only reads files, never shows values, and never deletes or moves anything."))
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            HStack {
                Text(model.folderPath ?? String(localized: "secret_scan.noFolder", defaultValue: "No folder chosen"))
                    .font(.system(size: 12)).lineLimit(1).truncationMode(.middle).foregroundStyle(theme.text)
                Spacer()
                Button(String(localized: "secret_scan.chooseFolder.button", defaultValue: "Choose folder…")) { model.chooseFolder() }
                    .buttonStyle(PillButtonStyle(primary: false)).disabled(model.scanning)
                if model.scanning {
                    Button(String(localized: "secret_scan.cancel", defaultValue: "Stop")) { model.cancel() }.buttonStyle(PillButtonStyle(primary: false))
                } else {
                    Button(String(localized: "secret_scan.scan", defaultValue: "Scan")) { model.scan() }
                        .buttonStyle(PillButtonStyle(primary: true)).disabled(model.folderPath == nil)
                }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(model.findings) { finding in
                        HStack(spacing: 10) {
                            Toggle("", isOn: Binding(get: { model.selected.contains(finding.id) },
                                                     set: { on in if on { model.selected.insert(finding.id) } else { model.selected.remove(finding.id) } }))
                                .toggleStyle(.checkbox).labelsHidden().disabled(model.imported[finding.id] != nil)
                                .accessibilityLabel(String(localized: "secret_scan.select", defaultValue: "Select \(finding.url.lastPathComponent)"))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(finding.url.lastPathComponent).font(.system(size: 13)).foregroundStyle(theme.text)
                                Text(finding.url.deletingLastPathComponent().path).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Text(detail(finding)).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
            .frame(minHeight: 160, maxHeight: 320)
            if let message = model.message { Text(message).font(.system(size: 12)).foregroundStyle(theme.textMuted) }
            Text(String(localized: "secret_scan.never", defaultValue: "Importing copies a file into your vault. The file itself stays where it is."))
                .font(.system(size: 11)).foregroundStyle(theme.textFaint)
            HStack {
                Spacer()
                Button(String(localized: "Close"), action: onClose).keyboardShortcut(.cancelAction)
                Button(String(localized: "secret_scan.import", defaultValue: "Import selected")) { model.importSelected() }
                    .keyboardShortcut(.defaultAction).disabled(model.selected.isEmpty || model.scanning)
            }
        }
        .padding(20).frame(width: 560)
        .foregroundStyle(theme.text)
    }

    private func detail(_ finding: SecretScanner.Finding) -> String {
        if model.imported[finding.id] != nil { return String(localized: "secret_scan.inVault", defaultValue: "In your vault") }
        switch finding.kind {
        case .sshPrivateKey: return String(localized: "secret_scan.kind.ssh", defaultValue: "SSH private key")
        case .envFile:
            return String(localized: "secret_scan.kind.env", defaultValue: ".env file") + " · "
                + String(localized: "secret_scan.vars", defaultValue: "Variables: \(finding.varCount)")
        }
    }
}
