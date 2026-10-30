import Foundation

/// Dashlane CSV files (credentials, secure notes, payments, IDs, personal info, legacy single file).
/// The zip of all five is opened through `ZipReader` (Windows `load_dashlane_zip`).
public enum DashlaneImport: Importer {
    private static let idTypes = ["card": "ID card", "passport": "Passport", "license": "Driving licence",
                                  "driver_license": "Driving licence", "social_security": "Social security number",
                                  "tax_number": "Tax number"]
    private static let personalMap: [(String, String)] = [
        ("first name", "given_name"), ("middle name", "middle_name"), ("last name", "family_name"), ("email", "email"),
        ("phone number", "phone"), ("address", "address_line1"), ("country", "country"), ("state", "state"), ("city", "city"),
        ("zip", "postal_code"), ("job title", "job_title"), ("url", "website"),
    ]

    /// Windows `classify_header`.
    static func classify(_ header: [String]) -> String {
        let keys = Set(header.map(CSVTable.normalizeHeader))
        func has(_ s: Set<String>) -> Bool { s.isSubset(of: keys) }
        if has(["cc number", "account name"]) || has(["cc number", "expiration month"]) { return "payments" }
        if has(["first name", "last name", "item name"]) { return "personal" }
        if has(["type", "number", "name", "issue date", "expiration date"]) { return "ids" }
        if has(["title", "password"]), !keys.isDisjoint(with: ["username2", "otpsecret", "otpurl", "category"]) { return "credentials" }
        if keys == ["title", "note"] || keys == ["title", "note", "category"] { return "notes" }
        if has(["title", "url", "password"]) { return "credentials" }
        return ""
    }

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let source = try ImportText.bounded(data, limit: ImportSource.maxArchiveBytes)
        if source.starts(with: [0x50, 0x4B]) { return try zip(source) }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        try load(ImportText.text(source), name: nil, &records, &diagnostics)
        return try ImportRules.result(records, diagnostics)
    }

    static let zipFiles = ["credentials.csv", "securenotes.csv", "payments.csv", "ids.csv", "personalinfo.csv"]
    static let maxZipMemberBytes = 8 * 1024 * 1024

    /// Windows `_load_text`: one CSV, its layout from the header (unknown columns: credentials, or skipped in a zip).
    static func load(_ text: String, name: String?, _ records: inout [ImportRecord], _ diagnostics: inout [String]) throws {
        let (header, rows) = try CSVTable.read(text)
        var layout = classify(header)
        if layout.isEmpty {
            if let name { diagnostics.append("\(name): columns not recognised; skipped."); return }
            layout = "credentials"
        }
        let offset = records.count
        switch layout {
        case "notes": notes(rows, &records)
        case "payments": payments(rows, &records)
        case "ids": ids(rows, &records)
        case "personal": personal(rows, &records)
        default: credentials(rows, &records)
        }
        if name != nil {
            for i in offset..<records.count { records[i].row = nil }  // row numbers repeat across the files of a zip
        }
    }

    /// Windows `load_dashlane_zip`: every recognised CSV, matched by file name in any folder.
    static func zip(_ source: Data) throws -> ImportResult {
        let corrupt = "The Dashlane archive is corrupted or unsupported"
        let reader: ZipReader
        do { reader = try ZipReader(data: source, maxBytes: ImportSource.maxArchiveBytes, maxEntries: ZipReader.defaultMaxEntries) }
        catch let f as ZipReader.Failure { throw OnePassword1PUX.archiveError(f, corrupt: corrupt) }
        var members: [String: ZipEntry] = [:]
        for e in reader.entries() {
            members[Py.casefold(String(e.name.split(separator: "/", omittingEmptySubsequences: false).last ?? ""))] = e
        }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        var found = false
        let space: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C]
        for name in zipFiles {
            guard let e = members[name] else { continue }
            if e.uncompressedSize > maxZipMemberBytes || e.isEncrypted || !(e.method == 0 || e.method == 8) {
                throw ImportError.malformed("\(name) inside the zip is too large, encrypted or unsupported")
            }
            let raw: Data
            do { raw = try reader.read(e, limit: maxZipMemberBytes) }
            catch ZipReader.Failure.tooLarge { throw ImportError.malformed("\(name) inside the zip is too large") }
            catch let f as ZipReader.Failure { throw OnePassword1PUX.archiveError(f, corrupt: corrupt) }
            found = true
            if raw.contains(where: { !space.contains($0) }) {
                try load(ImportText.decode(raw), name: name, &records, &diagnostics)
                try ImportRules.checkCount(records.count)
            }
        }
        guard found else {
            throw ImportError.malformed("The zip archive does not contain Dashlane CSV files (credentials.csv, securenotes.csv, ...)")
        }
        return try ImportRules.result(records, diagnostics)
    }

    static func credentials(_ rows: [CSVRow], _ out: inout [ImportRecord]) {
        for row in rows {
            let title = row.pick("title"), note = row.pick("note", "notes"), url = row.pick("url")
            let username = row.pick("username", "login", "email"), password = row.pick("password")
            if url.isEmpty, username.isEmpty, password.isEmpty {
                out.append(ImportRecord(kind: "note", title: title, notes: note, folder: row.pick("category"), row: row.number))
                continue
            }
            var r = ImportRecord(kind: "login", title: title.isEmpty ? url : title, username: username, password: password,
                                 urls: url.isEmpty ? [] : [url], notes: note,
                                 totp: ImportRules.totpURI(row.pick("otpUrl", "otpSecret", "totp"), label: title),
                                 folder: row.pick("category"), row: row.number)
            for extra in ["username2", "username3"] {
                let value = row.pick(extra)
                if !value.isEmpty, value != username { r.addField("Alternative username", value) }
            }
            out.append(r)
        }
    }

    static func notes(_ rows: [CSVRow], _ out: inout [ImportRecord]) {
        for row in rows {
            out.append(ImportRecord(kind: "note", title: row.pick("title"), notes: row.pick("note", "notes"),
                                    folder: row.pick("category"), row: row.number))
        }
    }

    static func payments(_ rows: [CSVRow], _ out: inout [ImportRecord]) {
        for row in rows {
            let kind = Py.casefold(row.pick("type"))
            let named = row.pick("account_name", "name")
            let title = !named.isEmpty ? named : (kind == "bank" ? "Bank account" : "Payment card")
            var r: ImportRecord
            if ["", "credit_card", "payment_card", "card"].contains(kind), !row.pick("cc_number").isEmpty {
                r = ImportRecord(kind: "card", title: title, notes: row.pick("note"), card: ImportRecord.cleanCard([
                    "cardholder": row.pick("account_holder"), "number": row.pick("cc_number"), "cvv": row.pick("code"),
                    "expiry": ImportRules.cardExpiry(row.pick("expiration_month"), row.pick("expiration_year")),
                ]), row: row.number)
                r.addField("Issuing bank", row.pick("issuing_bank"))
                r.addField("Country", row.pick("country"))
            } else {
                r = ImportRecord(kind: "note", title: title, notes: row.pick("note"), row: row.number)
                r.addField("Dashlane payment type", kind.isEmpty ? "unknown" : kind)
                r.addField("Account holder", row.pick("account_holder"))
                r.addField("Account number", row.pick("account_number"), hidden: true)
                r.addField("Routing number", row.pick("routing_number"), hidden: true)
                r.addField("Card number", row.pick("cc_number"), hidden: true)
                r.addField("Bank", row.pick("issuing_bank"))
                r.addField("Country", row.pick("country"))
            }
            out.append(r)
        }
    }

    static func ids(_ rows: [CSVRow], _ out: inout [ImportRecord]) {
        for row in rows {
            let kind = Py.casefold(row.pick("type"))
            let fallback = Py.capitalize(kind.replacingOccurrences(of: "_", with: " "))
            let label = idTypes[kind] ?? (fallback.isEmpty ? "ID document" : fallback)
            let name = row.pick("name")
            var r = ImportRecord(kind: "note", title: name.isEmpty ? label : "\(label) - \(name)", row: row.number)
            r.addField("Document type", label)
            r.addField("Number", row.pick("number"), hidden: true)
            r.addField("Name", name)
            for (column, field) in [("issue_date", "Issue date"), ("expiration_date", "Expiry date"),
                                    ("place_of_issue", "Place of issue"), ("state", "State")] {
                r.addField(field, row.pick(column))
            }
            out.append(r)
        }
    }

    static func personal(_ rows: [CSVRow], _ out: inout [ImportRecord]) {
        for row in rows {
            var values: [String: String] = [:]
            for (column, target) in personalMap {
                let v = row.get(column)
                if !v.isEmpty, values[target] == nil { values[target] = v }
            }
            let full = Py.split(["given_name", "middle_name", "family_name"].map { values[$0] ?? "" }.joined(separator: " "))
            if !full.isEmpty { values["name"] = full.joined(separator: " ") }
            var title = row.pick("item_name", "title")
            if title.isEmpty { title = values["name"] ?? "" }
            if title.isEmpty { title = Py.capitalize(row.pick("type")) }
            if title.isEmpty { title = "Personal info" }
            var r = ImportRecord(kind: "identity", title: title, identity: values, row: row.number)
            for (column, field) in [("date_of_birth", "Date of birth"), ("place_of_birth", "Place of birth"), ("login", "Login"),
                                    ("address_recipient", "Recipient"), ("address_building", "Building"),
                                    ("address_apartment", "Apartment"), ("address_floor", "Floor"),
                                    ("address_door_code", "Door code")] {
                r.addField(field, row.pick(column), hidden: column == "address_door_code")
            }
            out.append(r)
        }
    }
}
