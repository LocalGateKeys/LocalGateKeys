import Foundation

/// Credential Exchange (CXF v1.0) account export, the inverse of `CXFImport` (the Windows `exporters/cxf.py` and
/// Android `CxfExport`): one `Account` document with an item per record, so a file written here imports back into
/// the same records.
///
/// * login -> `basic-auth` (always, even when empty), its 2FA setup as a `totp` credential, its notes as a `note`;
/// * note -> an item with a single `note` credential;
/// * passkey -> a `passkey` credential whose `key` is the base64url PKCS#8 DER private key.
///
/// Only the selected items are exported. `plan` never reads a private key: `finish` takes them from the caller,
/// which releases them only after the app's owner check, and a missing key means nothing is made. The document
/// is built fully in memory, so a failed export leaves no file behind. Descriptions show counts, never values.
public enum CXFExport {
    /// Something the export left out, named so the person knows (`title` is "" for an item deleted since it was
    /// listed).
    public struct Diagnostic: Sendable, Equatable {
        /// `passkeyUnreadable`: a passkey whose stored credential id does not decode; it is skipped, never written
        /// with an empty id (the importer would drop it).
        public enum Kind: Sendable, Equatable { case fieldsLeftOut, kindSkipped, passkeyNotesLeftOut, passkeyUnreadable }
        public let kind: Kind
        public let title: String
        public init(kind: Kind, title: String) { self.kind = kind; self.title = title }
    }

    /// An export that made nothing.
    public enum Failure: Error, Equatable, Sendable {
        case chooseItems
        case passkeyKeyMissing(title: String)
        /// `accountJSON` was given a passkey with an empty credential id.
        case passkeyUnreadable(title: String)
        case nothingToExport
        /// `accountJSON` was given a card or an identity (CXF export holds logins, notes and passkeys only).
        case unsupportedKind
    }

    /// The selected items as candidates, passkeys still without their private keys.
    public struct Plan: Sendable, CustomStringConvertible {
        struct Entry: Sendable {
            let id: String
            let candidate: ImportCandidate
        }
        let entries: [Entry]
        /// The item ids of the selected passkeys, in selection order.
        public let passkeyIDs: [String]
        public let diagnostics: [Diagnostic]
        public var count: Int { entries.count }
        public var description: String {
            "CXFExport.Plan(records: \(entries.count), passkeys: \(passkeyIDs.count), diagnostics: \(diagnostics.count))"
        }
    }

    /// The file's bytes (plain-text secrets: write them, then drop them) and what it holds.
    public struct Result: Sendable, CustomStringConvertible {
        public let data: Data
        public let count: Int
        public let diagnostics: [Diagnostic]
        public var description: String {
            "CXFExport.Result(size: \(data.count), count: \(count), diagnostics: \(diagnostics.count))"
        }
    }

    // MARK: candidates -> document

    /// One CXF `Account` document with an item per candidate (logins, notes and passkeys; anything else throws
    /// `Failure.unsupportedKind`). `now` dates items whose modification time is unknown.
    public static func accountJSON(_ items: [ImportCandidate], now: Date, random: any RandomSource = SystemRandomSource(),
                                   exporterName: String = "LocalGateKeys") throws -> Data {
        let stamp = Int64(now.timeIntervalSince1970.rounded(.down))
        var rows = [JSONValue]()
        rows.reserveCapacity(items.count)
        for c in items { rows.append(try item(c, now: stamp, random: random)) }
        let doc: JSONValue = .object([
            "id": .string(newID(random)), "username": .string(exporterName), "email": .string(""),
            "collections": .array([]), "items": .array(rows), "extensions": .array([]),
        ])
        return Data(try CanonicalJSON.encode(doc, dialect: .utf8))
    }

    private static func newID(_ random: any RandomSource) -> String { base64URLNoPad(random.bytes(count: 16)) }

    private static func field(_ value: String, _ random: any RandomSource, type: String = "string") -> JSONValue {
        .object(["id": .string(newID(random)), "fieldType": .string(type), "value": .string(value)])
    }

    /// An `otpauth://totp` URI split into a CXF `totp` credential, or nil when it is not a valid one.
    static func totpCredential(_ uri: String) -> JSONValue? {
        guard let account = try? OTPAccount(otpauth: uri) else { return nil }
        let config = account.config
        var out: [String: JSONValue] = [
            "type": .string("totp"), "secret": .string(config.secret), "period": .int(Int64(config.period)),
            "digits": .int(Int64(config.digits)), "algorithm": .string(config.algorithm.lowercased()),
        ]
        if !account.account.isEmpty { out["username"] = .string(account.account) }
        if !account.issuer.isEmpty { out["issuer"] = .string(account.issuer) }
        return .object(out)
    }

    private static func item(_ c: ImportCandidate, now: Int64, random: any RandomSource) throws -> JSONValue {
        var credentials = [JSONValue]()
        switch c.kind {
        case .login(let f):
            // Always present, even when empty: without it the importer would read the item as a note (or drop it).
            credentials.append(.object(["type": .string("basic-auth"), "username": field(f.username, random),
                                        "password": field(f.password, random, type: "concealed-string")]))
            if let uri = f.otpauth, !uri.isEmpty, let totp = totpCredential(uri) { credentials.append(totp) }
            if !f.notes.isEmpty { credentials.append(.object(["type": .string("note"), "content": field(f.notes, random)])) }
        case .note(let f):
            credentials.append(.object(["type": .string("note"), "content": field(f.notes, random)]))
        case .passkey(let p):
            guard !p.credentialID.isEmpty else { throw Failure.passkeyUnreadable(title: c.title) }
            credentials.append(.object([
                "type": .string("passkey"), "credentialId": .string(base64URLNoPad(Array(p.credentialID))),
                "rpId": .string(p.rpID), "username": .string(p.userName), "userDisplayName": .string(p.userDisplayName),
                "userHandle": .string(base64URLNoPad(Array(p.userHandle))), "key": .string(base64URLNoPad(Array(p.pkcs8))),
            ]))
        case .card, .identity:
            throw Failure.unsupportedKind
        }
        var out: [String: JSONValue] = ["id": .string(newID(random))]
        let created = c.created.flatMap { $0 != 0 ? $0 : nil }
        if let created { out["creationAt"] = .int(created) }
        out["modifiedAt"] = .int(c.modified.flatMap { $0 != 0 ? $0 : nil } ?? created ?? now)
        out["title"] = .string(c.title)
        out["scope"] = .object(["urls": .array(c.urls.map { JSONValue.string($0) }), "androidApps": .array([])])
        out["credentials"] = .array(credentials)
        return .object(out)
    }

    // MARK: vault -> candidates

    private static func str(_ v: JSONValue?) -> String {
        switch v {
        case .string(let s)?: return s
        case .int(let i)?: return String(i)
        default: return ""
        }
    }

    private static func obj(_ v: JSONValue?) -> [String: JSONValue] {
        if case .object(let o)? = v { return o }
        return [:]
    }

    private static func arr(_ v: JSONValue?) -> [JSONValue] {
        if case .array(let a)? = v { return a }
        return []
    }

    private static func stamp(_ v: JSONValue?) -> Int64? {
        if case .int(let i)? = v, i != 0 { return i }
        return nil
    }

    /// `YYYY-MM-DD` as Unix seconds at midnight UTC, or nil.
    private static func dayStamp(_ text: String) -> Int64? {
        let parts = text.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
              parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        guard let utc = TimeZone(identifier: "UTC") else { return nil }
        calendar.timeZone = utc
        guard let date = calendar.date(from: DateComponents(year: y, month: m, day: d)) else { return nil }
        let back = calendar.dateComponents([.year, .month, .day], from: date)
        guard back.year == y, back.month == m, back.day == d else { return nil }
        return Int64(date.timeIntervalSince1970)
    }

    /// The live record of `id` and its namespace, or nil when missing or deleted.
    private static func live(_ snapshot: StoreSnapshot, _ id: String) -> (ns: String, record: [String: JSONValue])? {
        if snapshot.meta[id]?.deleted == true { return nil }
        // A collection state is never an item (`StoreSnapshot.itemRecords`).
        if CollectionStates.isReserved(id, snapshot.records[id]) { return nil }
        let w = obj(snapshot.records[id])
        guard case .string(let ns)? = w["ns"], case .object(let r)? = w["record"] else { return nil }
        return (ns, r)
    }

    private static func entryURLs(_ r: [String: JSONValue]) -> [String] {
        let scope = obj(r["scope"])
        let urls = arr(scope["urls"]).map { str(obj($0)["url"]) }.filter { !$0.isEmpty }
        if !urls.isEmpty { return urls }
        let origin = str(scope["origin"])
        return origin.isEmpty ? [] : [origin]
    }

    /// The login as a candidate, and whether it held data CXF has no place for (custom fields, recovery codes,
    /// a desktop program's path or window).
    private static func login(_ r: [String: JSONValue], includeTOTP: Bool) -> (candidate: ImportCandidate, dropped: Bool) {
        let web = r["kind"] == .string("web")
        let scope = obj(r["scope"])
        let origin = str(scope["origin"])
        let username = str(r["username"])
        let label = str(r["label"])
        var otpauth: String?
        let t = obj(r["totp"])
        if includeTOTP, let secret = try? TOTP.normalizeSecret(str(t["secret"])), !secret.isEmpty {
            var digits = 6, period = 30
            if case .int(let n)? = t["digits"], n != 0 { digits = Int(n) }
            if case .int(let n)? = t["period"], n != 0 { period = Int(n) }
            let algorithm = str(t["algorithm"]).isEmpty ? "SHA1" : str(t["algorithm"]).uppercased()
            otpauth = OTPAccount(issuer: str(t["issuer"]), account: username,
                                 config: TOTPConfig(secret: secret, algorithm: algorithm, digits: digits, period: period)).uri
        }
        let dropped = !arr(r["custom_fields"]).isEmpty
            || arr(r["recovery_codes"]).contains { !str($0).isEmpty }
            || (!web && (!str(scope["exe_path"]).isEmpty || !str(scope["window_title"]).isEmpty))
        let urls = web ? entryURLs(r) : []
        let title = label.isEmpty ? (web && !origin.isEmpty ? origin : "Credential") : label
        let fields = LoginFields(url: urls.first ?? "", username: username, password: str(r["password"]),
                                 notes: str(r["notes"]), otpauth: otpauth)
        let candidate = ImportCandidate(title: title, kind: .login(fields), urls: urls,
                                        created: stamp(r["created_at"]), modified: stamp(r["updated_at"]))
        return (candidate, dropped)
    }

    /// The passkey without its private key (added by `finish` once released), and whether its credential id
    /// decoded (an empty or unreadable one would be lost on import).
    private static func passkey(_ r: [String: JSONValue]) -> (candidate: ImportCandidate, readable: Bool) {
        let p = obj(r["payload"])
        let rp = str(p["relying_party_id"])
        let credentialID = decodeBase64URL(Normalise.pyStrip(str(p["credential_id"])), maxBytes: 1023) ?? []
        let fields = PasskeyFields(
            rpID: rp, userName: str(p["user_name"]), userDisplayName: str(p["user_display_name"]),
            userHandle: Data(decodeBase64URL(Normalise.pyStrip(str(p["user_handle"])), maxBytes: 1024) ?? []),
            credentialID: Data(credentialID), pkcs8: Data())
        let title = str(r["title"]).isEmpty ? rp : str(r["title"])
        let candidate = ImportCandidate(title: title, kind: .passkey(fields), urls: rp.isEmpty ? [] : ["https://\(rp)"],
                                        created: dayStamp(str(p["created"])) ?? stamp(r["created_at"]))
        return (candidate, !credentialID.isEmpty)
    }

    /// Collects the selected items (`ids`, in order, repeats dropped); throws `Failure.chooseItems` for none.
    /// Reads no private key.
    public static func plan(snapshot: StoreSnapshot, ids: [String], includeTOTP: Bool = true) throws -> Plan {
        var seen = Set<String>()
        let wanted = ids.filter { seen.insert($0).inserted }
        guard !wanted.isEmpty else { throw Failure.chooseItems }
        var entries = [Plan.Entry]()
        var passkeyIDs = [String]()
        var diagnostics = [Diagnostic]()
        for id in wanted {
            guard let found = live(snapshot, id) else {
                // Deleted since it was listed: no title to show (never the raw id).
                diagnostics.append(Diagnostic(kind: .kindSkipped, title: ""))
                continue
            }
            let (ns, r) = found
            let kind = str(r["kind"])
            if ns == Namespace.entry.rawValue, kind == "web" || kind == "desktop" {
                let made = login(r, includeTOTP: includeTOTP)
                entries.append(Plan.Entry(id: id, candidate: made.candidate))
                if made.dropped { diagnostics.append(Diagnostic(kind: .fieldsLeftOut, title: made.candidate.title)) }
            } else if ns == Namespace.item.rawValue, kind == "passkey" {
                let (candidate, readable) = passkey(r)
                guard readable else {
                    diagnostics.append(Diagnostic(kind: .passkeyUnreadable, title: candidate.title))
                    continue
                }
                if !str(obj(r["payload"])["notes"]).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    diagnostics.append(Diagnostic(kind: .passkeyNotesLeftOut, title: candidate.title))
                }
                passkeyIDs.append(id)
                entries.append(Plan.Entry(id: id, candidate: candidate))
            } else if ns == Namespace.item.rawValue, kind == "note" {
                let p = obj(r["payload"])
                let candidate = ImportCandidate(title: str(r["title"]), kind: .note(NoteFields(notes: str(p["body"]))),
                                                created: stamp(r["created_at"]), modified: stamp(r["updated_at"]))
                if !arr(p["fields"]).isEmpty { diagnostics.append(Diagnostic(kind: .fieldsLeftOut, title: candidate.title)) }
                entries.append(Plan.Entry(id: id, candidate: candidate))
            } else {
                let title = str(r["title"]).isEmpty ? str(r["label"]) : str(r["title"])
                diagnostics.append(Diagnostic(kind: .kindSkipped, title: title))
            }
        }
        return Plan(entries: entries, passkeyIDs: passkeyIDs, diagnostics: diagnostics)
    }

    /// The stored private keys (base64url PKCS#8) of the passkeys `ids`: what the app releases after its owner check.
    public static func privateKeys(snapshot: StoreSnapshot, ids: [String]) -> [String: String] {
        var out = [String: String]()
        for id in ids {
            guard let found = live(snapshot, id), found.ns == Namespace.item.rawValue,
                  found.record["kind"] == .string("passkey") else { continue }
            let key = str(obj(found.record["payload"])["private_key"])
            if !key.isEmpty { out[id] = key }
        }
        return out
    }

    /// The file for `plan` with the `released` private keys (item id -> base64url PKCS#8). Every selected passkey
    /// needs its key, or `Failure.passkeyKeyMissing` and nothing is made.
    public static func finish(_ plan: Plan, released: [String: String], now: Date,
                              random: any RandomSource = SystemRandomSource(),
                              exporterName: String = "LocalGateKeys") throws -> Result {
        var items = [ImportCandidate]()
        items.reserveCapacity(plan.entries.count)
        defer {
            // Zero the private keys copied in here (each `Data` is uniquely held once its item is replaced).
            for i in items.indices {
                guard case .passkey(var fields) = items[i].kind else { continue }
                items[i].kind = .note(NoteFields(notes: ""))
                fields.pkcs8.resetBytes(in: 0..<fields.pkcs8.count)
            }
            items.removeAll()
        }
        for entry in plan.entries {
            guard case .passkey(var fields) = entry.candidate.kind else { items.append(entry.candidate); continue }
            guard let text = released[entry.id], var der = decodeBase64URL(Normalise.pyStrip(text), maxBytes: 4096),
                  !der.isEmpty else {
                throw Failure.passkeyKeyMissing(title: entry.candidate.title)
            }
            fields.pkcs8 = Data(der)
            for i in der.indices { der[i] = 0 }
            var candidate = entry.candidate
            candidate.kind = .passkey(fields)
            items.append(candidate)
        }
        guard !items.isEmpty else { throw Failure.nothingToExport }
        let data = try accountJSON(items, now: now, random: random, exporterName: exporterName)
        return Result(data: data, count: items.count, diagnostics: plan.diagnostics)
    }

    /// The selected items (`ids`) as a CXF file. `release` gets the ids of the selected passkeys and returns their
    /// private keys; it is called only when a passkey is selected, after every other record is collected, and
    /// anything it throws (the person declined) propagates with nothing made.
    public static func export(snapshot: StoreSnapshot, ids: [String], release: ([String]) throws -> [String: String],
                              now: Date, random: any RandomSource = SystemRandomSource(),
                              includeTOTP: Bool = true) throws -> Result {
        let selected = try plan(snapshot: snapshot, ids: ids, includeTOTP: includeTOTP)
        var released = try (selected.passkeyIDs.isEmpty ? [:] : release(selected.passkeyIDs))
        defer { released.removeAll() }   // written, refused or failed: the keys are not kept
        return try finish(selected, released: released, now: now, random: random)
    }
}
