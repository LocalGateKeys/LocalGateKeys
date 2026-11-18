import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Writes the vault to a temporary file for the share sheet: an encrypted `LGKMBAK1` backup (every record,
/// tombstones included), an unencrypted Apple Passwords CSV (live web logins only) or an unencrypted CXF file
/// (the logins, notes and passkeys chosen). Export is never Pro-gated.
/// The caller deletes the file once the sheet closes (`VaultExporter.discard`).
@MainActor
struct VaultExporter {
    enum Error: Swift.Error, Equatable {
        case weakPassword, mismatch
    }

    static let minPasswordLength = 12

    let store: any ItemStore
    let isPro: () -> Bool
    let appVersion: String
    /// The keychain install id; a backup outside a sync group is written under a UUID5 of it.
    let fallbackDeviceID: () throws -> String
    let now: () -> Date
    let random: any RandomSource
    /// This device's attachment files; the backup carries the live documents' files from here (format 2).
    var blobs: (any AttachmentBlobStore)? = nil
    /// Items this device keeps out of the unencrypted CSV and CXF files (iPhone: travel mode and logins that are view
    /// only on phones, feature pack §2 and §4). Encrypted backups still hold every item. Empty by default.
    var leftOut: @MainActor (StoreSnapshot) -> Set<String> = { _ in [] }

    /// A sealed backup and how many document files did not fit in it (or were missing on this device).
    struct Sealed: Sendable {
        let data: Data
        let filesLeftOut: Int
    }

    /// Checks the password (at least 12 characters, both entries equal), then seals the backup off the main
    /// actor (Argon2id at 128 MiB takes a moment). The password is not kept.
    func encryptedBackup(password: String, confirmation: String) async throws -> URL {
        try await encryptedBackupFile(password: password, confirmation: confirmation).url
    }

    /// `encryptedBackup`, plus how many document files were left out of it.
    func encryptedBackupFile(password: String, confirmation: String) async throws -> (url: URL, filesLeftOut: Int) {
        let date = now()
        let sealed = try await sealedBackup(password: password, confirmation: confirmation, date: date)
        return (try Self.write(sealed.data, name: "LocalGateKeys-Backup-\(Self.day(date)).lgkm"), sealed.filesLeftOut)
    }

    /// The sealed backup bytes (the Mac writes them to the file the person chose).
    func encryptedBackupData(password: String, confirmation: String, date: Date? = nil) async throws -> Data {
        try await sealedBackup(password: password, confirmation: confirmation, date: date).data
    }

    /// Seals every state; live documents carry their files while they fit (`PhoneBackup.selectFiles`: state id
    /// order, 160 MiB, 500 files). A document whose file does not fit or is missing stays without it and is counted.
    func sealedBackup(password: String, confirmation: String, date: Date? = nil) async throws -> Sealed {
        guard password.count >= Self.minPasswordLength else { throw Error.weakPassword }
        guard password.utf8.elementsEqual(confirmation.utf8) else { throw Error.mismatch }
        let snap = try store.load()
        let date = date ?? now()
        let device = try Self.deviceID(snapshot: snap, installID: fallbackDeviceID)
        let view = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: device,
                                          now: Int64(date.timeIntervalSince1970))
        // Commit the vectors the backup carries first (as a sync run does), so an edit made after the export
        // always gets a newer vector than the backup's copy. A stale or locked store aborts the export.
        if view.meta != snap.meta {
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: view.meta, sync: snap.sync))
        }
        // The emergency access plan (`heir:plan`, which holds the plan's signing seed) never leaves the vault in an
        // export (review 5b M3): it travels only by sync, to the owner's own devices.
        let states = view.states.values.filter { !Self.isHeirState($0.itemID) }
            .map { BackupState(id: $0.itemID, deleted: $0.deleted, deletedAt: $0.deletedAt, item: $0.item, vv: $0.vv) }
        let appVersion = appVersion, proHint = isPro(), random = random, blobs = blobs
        return try await Task.detached(priority: .userInitiated) {
            let selected = PhoneBackup.selectFiles(Array(states)) { ref in blobs?.read(ref.blob) }
            let data = try PhoneBackup.seal(states: Array(states), password: password, appVersion: appVersion, deviceID: device,
                                            proHint: proHint, now: date, random: random, files: selected.files)
            return Sealed(data: data, filesLeftOut: selected.leftOut.count)
        }.value
    }

    /// A state of the `heir` namespace (the owner's plan): kept out of every export.
    nonisolated static func isHeirState(_ id: String) -> Bool { id == Heir.stateID || id.hasPrefix(Namespace.heir.rawValue + ":") }

    /// The live web logins as `Title,URL,Username,Password,Notes,OTPAuth` (passkeys cannot go in a CSV).
    func csv() throws -> URL {
        try Self.write(Data(try csvText().utf8), name: "LocalGateKeys-Export-\(Self.day(now())).csv")
    }

    /// The CSV text itself (the Mac writes it to the file the person chose).
    func csvText() throws -> String {
        let snap = try store.load()
        let skip = leftOut(snap)
        var rows: [(title: String, login: LoginFields)] = []
        for (id, wrapper) in snap.itemRecords where snap.meta[id]?.deleted != true && !skip.contains(id) {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let r)? = w["record"], r["kind"] == .string("web") else { continue }
            let title = r["label"]?.stringValue ?? ""
            let login = LoginFields(url: r["scope"]?.objectValue?["origin"]?.stringValue ?? "",
                                    username: r["username"]?.stringValue ?? "",
                                    password: r["password"]?.stringValue ?? "",
                                    notes: r["notes"]?.stringValue ?? "",
                                    otpauth: Self.otpauth(r["totp"], label: title))
            rows.append((title, login))
        }
        rows.sort { ($0.title.lowercased(), $0.login.url, $0.login.username) < ($1.title.lowercased(), $1.login.url, $1.login.username) }
        return CSVExport.appleCSV(logins: rows.map(\.login), titles: rows.map(\.title))
    }

    // MARK: CXF

    /// One item a CXF file can hold, by title (the selection list shows no secret).
    struct CXFChoice: Identifiable, Equatable, Sendable {
        enum Kind: Sendable { case login, note, passkey }
        let id: String
        let title: String
        let kind: Kind
        /// The site and username of a login, the username of a passkey ("" for a note).
        let detail: String
    }

    /// The live logins, notes and passkeys, sorted by title.
    func cxfChoices() throws -> [CXFChoice] {
        let snap = try store.load()
        let skip = leftOut(snap)
        var out: [CXFChoice] = []
        for (id, wrapper) in snap.itemRecords where snap.meta[id]?.deleted != true && !skip.contains(id) {
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"], case .object(let r)? = w["record"] else { continue }
            let kind = r["kind"]?.stringValue ?? ""
            if ns == Namespace.entry.rawValue, kind == "web" || kind == "desktop" {
                let origin = r["scope"]?.objectValue?["origin"]?.stringValue ?? ""
                let label = r["label"]?.stringValue ?? ""
                let title = label.isEmpty ? origin : label
                let site = origin.hasPrefix("https://") ? String(origin.dropFirst("https://".count)) : origin
                let detail = [site, r["username"]?.stringValue ?? ""].filter { !$0.isEmpty && $0 != title }.joined(separator: " · ")
                out.append(CXFChoice(id: id, title: title, kind: .login, detail: detail))
            } else if ns == Namespace.item.rawValue, kind == "note" {
                out.append(CXFChoice(id: id, title: r["title"]?.stringValue ?? "", kind: .note, detail: ""))
            } else if ns == Namespace.item.rawValue, kind == "passkey" {
                let p = r["payload"]?.objectValue
                let title = r["title"]?.stringValue ?? ""
                out.append(CXFChoice(id: id, title: title.isEmpty ? (p?["relying_party_id"]?.stringValue ?? "") : title,
                                     kind: .passkey, detail: p?["user_name"]?.stringValue ?? ""))
            }
        }
        return out.sorted { ($0.title.lowercased(), $0.id) < ($1.title.lowercased(), $1.id) }
    }

    /// Throws `CXFExport.Failure` when `ids` hold nothing a CXF file can carry. Reads no private key: run it
    /// before the owner check, so a selection that cannot be written does not ask for it.
    func cxfCheck(ids: [String]) throws {
        guard try CXFExport.plan(snapshot: store.load(), ids: ids).count > 0 else { throw CXFExport.Failure.nothingToExport }
    }

    /// The CXF file for the selected `ids` (only those). Passkey private keys are read here, from the vault as it
    /// is now: call it only after the owner check. Nothing is written when it throws.
    func cxfData(ids: [String]) throws -> CXFExport.Result {
        let snap = try store.load()
        let skip = leftOut(snap)
        let ids = ids.filter { !skip.contains($0) }
        return try CXFExport.export(snapshot: snap, ids: ids, release: { CXFExport.privateKeys(snapshot: snap, ids: $0) },
                                    now: now(), random: random)
    }

    /// `cxfData` written to a temporary file for the share sheet, and what the file left out.
    func cxf(ids: [String]) throws -> (url: URL, diagnostics: [CXFExport.Diagnostic]) {
        let result = try cxfData(ids: ids)
        return (try Self.write(result.data, name: Self.cxfFileName(now())), result.diagnostics)
    }

    /// `LocalGateKeys-CXF-YYYY-MM-DD.json`.
    static func cxfFileName(_ date: Date) -> String { "LocalGateKeys-CXF-\(day(date)).json" }

    /// What the file left out, in the person's language.
    nonisolated static func cxfDiagnostic(_ d: CXFExport.Diagnostic) -> String {
        let title = d.title
        switch d.kind {
        case .kindSkipped where title.isEmpty: return String(localized: "An item was deleted before the export and was skipped.")
        case .kindSkipped: return String(localized: "'\(title)' is not a login, note or passkey and was skipped.")
        case .fieldsLeftOut: return String(localized: "'\(title)': custom fields and recovery codes have no place in a CXF file and were left out.")
        case .passkeyNotesLeftOut: return String(localized: "'\(title)': passkey notes have no place in a CXF file and were left out.")
        case .passkeyUnreadable: return unreadablePasskey(title)
        }
    }

    nonisolated static func unreadablePasskey(_ title: String) -> String {
        String(localized: "'\(title)': this passkey's credential ID could not be read, so the passkey was skipped.")
    }

    /// Why nothing was exported.
    nonisolated static func cxfFailure(_ e: CXFExport.Failure) -> String {
        switch e {
        case .chooseItems: return String(localized: "Choose the items to export to the CXF file.")
        case .passkeyKeyMissing(let title): return String(localized: "The private key of passkey '\(title)' was not released; nothing was exported.")
        case .passkeyUnreadable(let title): return unreadablePasskey(title)
        case .nothingToExport, .unsupportedKind: return String(localized: "None of the selected items can be written to a CXF file.")
        }
    }

    nonisolated static let cxfFailedMessage = String(localized: "The CXF file could not be saved; nothing was exported.")

    /// The export's note when documents went into the backup without their files.
    nonisolated static func filesLeftOutMessage(_ count: Int) -> String {
        String(localized: "\(count) document files were left out of the backup (too large or not on this device); the documents themselves are in it.")
    }

    /// Deletes an exported file (after the share sheet closes, shared or cancelled).
    static func discard(_ url: URL?) {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: helpers

    nonisolated static let deviceNamespace = UUID5.make(namespace: UUID5.namespaceURL,
                                                        name: "https://localgatekeys.app/ios/backup-device")

    /// The sync group's device id, else a stable name-based UUID of this installation (Android `BackupDevice.id`).
    nonisolated static func deviceID(snapshot: StoreSnapshot, installID: () throws -> String) throws -> String {
        if let id = snapshot.sync?.deviceID { return id }
        return UUID5.string(UUID5.make(namespace: deviceNamespace, name: try installID()))
    }

    /// `otpauth://totp/<label>?secret=…&algorithm=…&digits=…&period=…` for a stored TOTP config.
    nonisolated static func otpauth(_ totp: JSONValue?, label: String) -> String? {
        guard case .object(let t)? = totp, case .string(let secret)? = t["secret"], !secret.isEmpty else { return nil }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let name = (label.isEmpty ? "LocalGateKeys" : label).addingPercentEncoding(withAllowedCharacters: allowed) ?? "LocalGateKeys"
        var uri = "otpauth://totp/\(name)?secret=\(secret)"
        if case .string(let a)? = t["algorithm"] { uri += "&algorithm=\(a)" }
        if case .int(let d)? = t["digits"] { uri += "&digits=\(d)" }
        if case .int(let p)? = t["period"] { uri += "&period=\(p)" }
        return uri
    }

    /// Deletes export files left in the temporary directory (the share sheet's owner was killed before `discard`).
    /// Run at launch; `directory` is overridable for tests.
    static func removeLeftoverExports(in directory: URL = FileManager.default.temporaryDirectory) {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory.path) else { return }
        for name in names where (name.hasPrefix("LocalGateKeys-Export-") && name.hasSuffix(".csv"))
            || (name.hasPrefix("LocalGateKeys-Backup-") && name.hasSuffix(".lgkm"))
            || (name.hasPrefix("LocalGateKeys-CXF-") && name.hasSuffix(".json")) {
            try? fm.removeItem(at: directory.appendingPathComponent(name))
        }
    }

    private static func write(_ data: Data, name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    private static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian); f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    static func day(_ date: Date) -> String { dayFormatter.string(from: date) }
}
