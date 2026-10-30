import Foundation

/// 1Password 1PUX archives (Windows `onepassword.load_1pux`): `export.data` inside a zip (or the bare JSON).
public enum OnePassword1PUX: Importer {
    static let maxExportDataBytes = 16 * 1024 * 1024
    static let corruptMessage = "1PUX archive is corrupted or unsupported"

    private static let loginCategories: Set<String> = ["001", "005", "102", "109", "110", "111", "112"]
    private static let categoryNames = [
        "001": "Login", "002": "Credit Card", "003": "Secure Note", "004": "Identity", "005": "Password",
        "006": "Document", "100": "Software License", "101": "Bank Account", "102": "Database",
        "103": "Driver License", "104": "Outdoor License", "105": "Membership", "106": "Passport",
        "107": "Reward Program", "108": "Social Security Number", "109": "Wireless Router", "110": "Server",
        "111": "Email Account", "112": "API Credential", "113": "Medical Record", "114": "Crypto Wallet",
    ]
    private static let identityIDs = [
        "firstname": "given_name", "initial": "middle_name", "lastname": "family_name", "company": "company",
        "jobtitle": "job_title", "email": "email", "defphone": "phone", "cellphone": "phone", "homephone": "phone",
        "busphone": "phone", "website": "website",
    ]
    private static let cardIDs = ["cardholder": "cardholder", "ccnum": "number", "cvv": "cvv", "expiry": "expiry",
                                  "pin": "pin", "type": "brand"]
    private static let addressKeys = [("street", "address_line1"), ("city", "city"), ("state", "state"),
                                      ("zip", "postal_code"), ("country", "country")]
    private static let sensitiveHints = ["password", "secret", "pin", "key", "number", "cvv", "code", "token", "seed", "passphrase"]

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        try records(exportData(data))
    }

    /// Windows `read_export_data`.
    static func exportData(_ data: Data) throws -> PyJSON {
        let source = try ImportText.bounded(data, limit: ImportSource.maxArchiveBytes)
        var raw = source
        if source.starts(with: [0x50, 0x4B]) {
            let zip: ZipReader
            do { zip = try ZipReader(data: source, maxBytes: ImportSource.maxArchiveBytes, maxEntries: ZipReader.defaultMaxEntries) }
            catch let f as ZipReader.Failure { throw archiveError(f) }
            guard let entry = zip.entry(named: "export.data") else {
                throw ImportError.malformed("1PUX archive does not contain export.data")
            }
            if entry.uncompressedSize > maxExportDataBytes { throw ImportError.malformed("export.data is too large") }
            if entry.isEncrypted {
                throw ImportError.malformed("export.data is encrypted inside the 1PUX archive; export again from 1Password")
            }
            guard entry.method == 0 || entry.method == 8 else {
                throw ImportError.malformed("export.data uses an unsupported ZIP compression method")
            }
            do { raw = try zip.read(entry, limit: maxExportDataBytes) }
            catch ZipReader.Failure.tooLarge { throw ImportError.malformed("export.data is too large") }
            catch let f as ZipReader.Failure { throw archiveError(f) }
        }
        if raw.count > maxExportDataBytes { throw ImportError.malformed("export.data is too large") }
        guard let doc = try? PyJSON.parse(ImportText.decode(raw)) else { throw ImportError.malformed("export.data is not valid JSON") }
        guard doc.isObject else { throw ImportError.malformed("export.data is not a 1Password export object") }
        return doc
    }

    /// Damage reads as the Windows message; what only the Mac refuses (unsafe names, zip bombs) keeps the reader's own.
    static func archiveError(_ f: ZipReader.Failure, corrupt: String = corruptMessage) -> ImportError {
        switch f {
        case .corrupt, .zip64, .unsupportedMethod, .encrypted: return .malformed(corrupt)
        default: return .malformed(f.message)
        }
    }

    /// Windows `records_from_export`.
    static func records(_ doc: PyJSON) throws -> ImportResult {
        guard case .array(let accounts)? = doc["accounts"] else {
            throw ImportError.malformed("export.data has no 'accounts' list")
        }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        var trashed = 0, index = 0
        for account in accounts where account.isObject {
            for vault in account["vaults"]?.list ?? [] where vault.isObject {
                let attrs = (vault["attrs"]?.isObject ?? false) ? vault["attrs"]! : .object([])
                let vaultName = PyJSON.text(attrs["name"])
                for item in vault["items"]?.list ?? [] {
                    index += 1
                    try ImportRules.checkCount(index)
                    guard item.isObject else { diagnostics.append("Item \(index): not an object; skipped."); continue }
                    if item["trashed"]?.truthy ?? false || Py.casefold(PyJSON.text(item["state"])) == "trashed" {
                        trashed += 1
                        continue
                    }
                    records.append(record(item, vaultName: vaultName, row: index))
                }
            }
        }
        if trashed > 0 { diagnostics.append("\(trashed) items in the 1Password trash were not imported.") }
        return try ImportRules.result(records, diagnostics)
    }

    private static func object(_ v: PyJSON?) -> PyJSON { (v?.isObject ?? false) ? v! : .object([]) }

    /// Windows `item_to_record`.
    static func record(_ item: PyJSON, vaultName: String, row: Int) -> ImportRecord {
        let overview = object(item["overview"]), details = object(item["details"])
        let categoryValue = item["categoryUuid"]
        let category = (categoryValue?.truthy ?? false) ? categoryValue!.str : "001"
        let title = PyJSON.text(overview["title"])
        var urls: [String] = []
        if overview["url"]?.truthy ?? false { urls.append(overview["url"]!.str) }
        for entry in overview["urls"]?.list ?? [] where entry.isObject {
            if let u = entry["url"], u.truthy, !urls.contains(u.str) { urls.append(u.str) }
        }
        var folder = vaultName
        if Py.casefold(PyJSON.text(item["state"])) == "archived" { folder = vaultName.isEmpty ? "Archive" : "\(vaultName)/Archive" }
        var r = ImportRecord(title: title, notes: PyJSON.text(details["notesPlain"]), folder: folder,
                             favourite: item["favIndex"]?.truthy ?? false, created: ImportTime.parse(item["createdAt"]),
                             modified: ImportTime.parse(item["updatedAt"]), tags: (overview["tags"]?.list ?? []).map(\.str), row: row)
        switch category {
        case "003": r.kind = "note"
        case "004": r.kind = "identity"
        case "002": r.kind = "card"
        case _ where loginCategories.contains(category):
            r.kind = "login"
            (r.username, r.password) = loginFields(details)
            r.urls = urls
        default:
            r.kind = "note"
            r.addField("1Password category", categoryNames[category] ?? category)
        }
        for section in details["sections"]?.list ?? [] where section.isObject {
            for field in section["fields"]?.list ?? [] where field.isObject {
                apply(field, to: &r, title: title)
            }
        }
        if r.kind == "identity" {
            let name = Py.strip(["given_name", "middle_name", "family_name"].map { r.identity[$0] ?? "" }.joined(separator: " "))
            if !name.isEmpty, r.identity["name"] == nil { r.identity["name"] = Py.split(name).joined(separator: " ") }
        }
        if category == "006" || (details["documentAttributes"]?.truthy ?? false) {
            r.addField("Attached file", "The file itself was not imported. Save it from 1Password and "
                       + "add it to LocalGateKeys as a document.")
        }
        return r
    }

    private static func apply(_ field: PyJSON, to r: inout ImportRecord, title: String) {
        let fieldID = Py.casefold(PyJSON.text(field["id"]))
        let titleValue = field["title"], idValue = field["id"]
        let label = (titleValue?.truthy ?? false) ? titleValue!.str : ((idValue?.truthy ?? false) ? idValue!.str : "")
        let (type, text) = fieldValue(field["value"])
        if text.isEmpty { return }
        if type == "totp" {
            if r.totp.isEmpty { r.totp = ImportRules.totpURI(text, label: title) }
            return
        }
        if r.kind == "identity" {
            if type == "address", let address = field["value"]?["address"], address.isObject {
                for (key, target) in addressKeys {
                    if let v = address[key], v.truthy { r.identity[target] = v.str }
                }
                return
            }
            if let target = identityIDs[fieldID], (r.identity[target] ?? "").isEmpty {
                r.identity[target] = text
                return
            }
        }
        if r.kind == "card", let target = cardIDs[fieldID], (r.card[target] ?? "").isEmpty {
            let value = fieldID == "expiry" ? ImportRules.cardExpiry(text) : text
            if !value.isEmpty { r.card[target] = value; return }
        }
        if r.kind == "login" {
            if fieldID == "username", r.username.isEmpty { r.username = text; return }
            if fieldID == "password", r.password.isEmpty { r.password = text; return }
        }
        if type == "url", r.kind == "login" {
            if !r.urls.contains(text) { r.urls.append(text) }
            return
        }
        let lowerLabel = Py.casefold(label)
        let hidden = ["concealed", "creditCardNumber", "sshKey"].contains(type) || (field["guarded"]?.truthy ?? false)
            || sensitiveHints.contains { fieldID.contains($0) || lowerLabel.contains($0) }
        r.addField(label, text, hidden: hidden)
    }

    /// Windows `_login_fields`.
    static func loginFields(_ details: PyJSON) -> (String, String) {
        var username = "", password = ""
        for field in details["loginFields"]?.list ?? [] where field.isObject {
            let designation = Py.casefold(PyJSON.text(field["designation"]))
            let value = PyJSON.text(field["value"])
            if designation == "username", username.isEmpty { username = value }
            else if designation == "password", password.isEmpty { password = value }
            else if designation.isEmpty, field["fieldType"] == .string("P"), password.isEmpty { password = value }
        }
        if password.isEmpty, details["password"]?.truthy ?? false { password = details["password"]!.str }
        return (username, password)
    }

    /// Windows `_field_value`: (type, text) of a section field value object.
    static func fieldValue(_ value: PyJSON?) -> (String, String) {
        guard let value, value.isObject, let key = value.firstKey, let raw = value[key] else { return ("", "") }
        if raw == .null { return (key, "") }
        if raw.isObject, key == "email" { return (key, PyJSON.text(raw["email_address"])) }
        if raw.isObject, key == "address" {
            let parts = ["street", "city", "state", "zip", "country"].map { PyJSON.text(raw[$0]) }
            return (key, parts.filter { !$0.isEmpty }.joined(separator: ", "))
        }
        var integer: Int64?
        if case .int(let i) = raw { integer = i }
        if case .bool(let b) = raw { integer = b ? 1 : 0 }
        if integer != nil {
            let text = raw.str
            if key == "monthYear" {
                let u = Array(text.unicodeScalars)
                return (key, u.count == 6 ? Py.scalars(u[4..<6]) + "/" + Py.scalars(u[0..<4]) : text)
            }
            if key == "date" { return (key, date(integer!) ?? text) }
            return (key, text)
        }
        if case .float(let f) = raw, key == "date", f.isFinite, abs(f) < 1e15 { return (key, date(Int64(f)) ?? raw.str) }
        if raw.isObject || raw.isList { return (key, dumps(raw)) }
        return (key, raw.str)
    }

    /// `datetime.fromtimestamp(int(raw), tz=UTC).strftime("%Y-%m-%d")`, nil where Python raises.
    private static func date(_ seconds: Int64) -> String? {
        let days = seconds >= 0 ? seconds / 86400 : -((-seconds + 86399) / 86400)
        // civil from days (Howard Hinnant)
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let y = yoe + era * 400 + (m <= 2 ? 1 : 0)
        guard (1...9999).contains(y) else { return nil }
        return String(format: "%04d-%02d-%02d", Int(y), Int(m), Int(d))
    }

    /// `json.dumps(value, ensure_ascii=False)`.
    static func dumps(_ v: PyJSON) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .int(let i): return String(i)
        case .float(let f):
            if f.isNaN { return "NaN" }
            if f.isInfinite { return f > 0 ? "Infinity" : "-Infinity" }
            return PythonFloat.repr(f)
        case .string(let s):
            var out = "\""
            for c in s.unicodeScalars {
                switch c {
                case "\"": out += "\\\""
                case "\\": out += "\\\\"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                case "\u{08}": out += "\\b"
                case "\u{0C}": out += "\\f"
                default:
                    if c.value < 0x20 { out += String(format: "\\u%04x", c.value) } else { out.unicodeScalars.append(c) }
                }
            }
            return out + "\""
        case .array(let a): return "[" + a.map { dumps($0) }.joined(separator: ", ") + "]"
        case .object(let pairs):
            var keys: [String] = []
            for (k, _) in pairs where !keys.contains(k) { keys.append(k) }
            return "{" + keys.map { dumps(.string($0)) + ": " + dumps(v[$0]!) }.joined(separator: ", ") + "}"
        }
    }
}
