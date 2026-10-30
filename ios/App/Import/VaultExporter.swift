import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Writes the vault to a temporary file for the share sheet: an encrypted `LGKMBAK1` backup (every record,
/// tombstones included) or an unencrypted Apple Passwords CSV (live web logins only). Export is never Pro-gated.
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
        let states = view.states.values
            .map { BackupState(id: $0.itemID, deleted: $0.deleted, deletedAt: $0.deletedAt, item: $0.item, vv: $0.vv) }
        let appVersion = appVersion, proHint = isPro(), random = random, blobs = blobs
        return try await Task.detached(priority: .userInitiated) {
            let selected = PhoneBackup.selectFiles(Array(states)) { ref in blobs?.read(ref.blob) }
            let data = try PhoneBackup.seal(states: Array(states), password: password, appVersion: appVersion, deviceID: device,
                                            proHint: proHint, now: date, random: random, files: selected.files)
            return Sealed(data: data, filesLeftOut: selected.leftOut.count)
        }.value
    }

    /// The live web logins as `Title,URL,Username,Password,Notes,OTPAuth` (passkeys cannot go in a CSV).
    func csv() throws -> URL {
        try Self.write(Data(try csvText().utf8), name: "LocalGateKeys-Export-\(Self.day(now())).csv")
    }

    /// The CSV text itself (the Mac writes it to the file the person chose).
    func csvText() throws -> String {
        let snap = try store.load()
        var rows: [(title: String, login: LoginFields)] = []
        for (id, wrapper) in snap.records where snap.meta[id]?.deleted != true {
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
            || (name.hasPrefix("LocalGateKeys-Backup-") && name.hasSuffix(".lgkm")) {
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
