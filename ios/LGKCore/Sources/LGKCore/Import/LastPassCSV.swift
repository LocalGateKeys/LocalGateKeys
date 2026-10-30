import Foundation

/// LastPass CSV (`url,username,password,totp,extra,name,grouping,fav`), templated secure notes included.
public enum LastPassCSV: Importer {
    static let secureNoteURL = "http://sn"
    private static let cardFields = ["name on card": "cardholder", "number": "number", "security code": "cvv",
                                     "expiration date": "expiry", "type": "brand", "pin": "pin"]
    private static let addressFields = [
        "first name": "given_name", "middle name": "middle_name", "last name": "family_name", "company": "company",
        "address 1": "address_line1", "address 2": "address_line2", "city / town": "city", "state": "state",
        "zip / postal code": "postal_code", "country": "country", "email address": "email", "phone": "phone",
        "mobile phone": "phone", "username": "username",
    ]

    /// Windows `parse_secure_note`: (type, fields in order, free notes).
    static func parseSecureNote(_ extra: String) -> (type: String, fields: [(String, String)], notes: String) {
        let lines = Py.splitlines(extra)
        guard let first = lines.first, first.hasPrefix("NoteType:") else { return ("", [], extra) }
        let type = Py.strip(String(first.dropFirst("NoteType:".count)))
        var fields: [(String, String)] = []
        var notes: [String] = []
        var inNotes = false
        for line in lines.dropFirst() {
            if inNotes { notes.append(line); continue }
            if line.hasPrefix("Notes:") {
                inNotes = true
                let remainder = String(line.dropFirst("Notes:".count))
                if !remainder.isEmpty { notes.append(remainder) }
                continue
            }
            if let (key, value) = Py.partition(line, ":") {
                let k = Py.strip(key)
                if let i = fields.firstIndex(where: { $0.0 == k }) { fields[i].1 = value } else { fields.append((k, value)) }
            } else if !Py.strip(line).isEmpty {
                notes.append(line)
            }
        }
        return (type, fields, notes.joined(separator: "\n"))
    }

    static func noteRecord(_ title: String, _ extra: String, _ folder: String, _ favourite: Bool, _ number: Int) -> ImportRecord {
        let (type, fields, notes) = parseSecureNote(extra)
        let kind = Py.casefold(type)
        if kind == "address" {
            var identity: [String: String] = [:]
            for (key, value) in fields {
                let target = addressFields[Py.casefold(key)]
                if target == "username" { continue }
                if let target, !value.isEmpty, (identity[target] ?? "").isEmpty { identity[target] = value }
            }
            let name = Py.split(["given_name", "middle_name", "family_name"].map { identity[$0] ?? "" }.joined(separator: " "))
            if !name.isEmpty { identity["name"] = name.joined(separator: " ") }
            var r = ImportRecord(kind: "identity", title: title, notes: notes, folder: folder, favourite: favourite,
                                 identity: identity, row: number)
            for (key, value) in fields where addressFields[Py.casefold(key)] == nil && !value.isEmpty
                && !["language", "title"].contains(Py.casefold(key)) {
                r.addField(key, value)
            }
            return r
        }
        if kind == "credit card" {
            var r = ImportRecord(kind: "card", title: title, notes: notes, folder: folder, favourite: favourite, row: number)
            for (key, raw) in fields {
                var target = cardFields[Py.casefold(key)]
                var value = raw
                if target == "expiry" {
                    let parsed = ImportRules.cardExpiry(raw)
                    if parsed.isEmpty { target = nil } else { value = parsed }
                }
                if let target, !value.isEmpty, (r.card[target] ?? "").isEmpty {
                    r.card[target] = Py.strip(value)
                } else if !value.isEmpty, Py.casefold(key) != "language" {
                    let hidden = ["number", "code", "pin"].contains { Py.casefold(key).contains($0) }
                    r.addField(key, value, hidden: hidden)
                }
            }
            return r
        }
        if !type.isEmpty {
            var r = ImportRecord(kind: "note", title: title, notes: notes, folder: folder, favourite: favourite, row: number)
            r.addField("LastPass note type", type)
            for (key, value) in fields where !value.isEmpty && Py.casefold(key) != "language" {
                let hidden = ["password", "pin", "secret", "number", "code", "key"].contains { Py.casefold(key).contains($0) }
                r.addField(key, value, hidden: hidden)
            }
            return r
        }
        return ImportRecord(kind: "note", title: title, notes: extra, folder: folder, favourite: favourite, row: number)
    }

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let (_, rows) = try CSVTable.read(ImportText.text(data))
        var records: [ImportRecord] = []
        for row in rows {
            let url = Py.strip(row.pick("url"))
            let name = row.pick("name")
            let folder = row.pick("grouping").replacingOccurrences(of: "\\", with: "/")
            let favourite = ImportRules.truthy(row.pick("fav"))
            let extra = row.pick("extra")
            if Py.casefold(url) == secureNoteURL || (url.isEmpty && row.pick("username").isEmpty && row.pick("password").isEmpty) {
                records.append(noteRecord(name, extra, folder, favourite, row.number))
                continue
            }
            records.append(ImportRecord(kind: "login", title: name.isEmpty ? url : name, username: row.pick("username"),
                                        password: row.pick("password"), urls: url.isEmpty ? [] : [url], notes: extra,
                                        totp: ImportRules.totpURI(row.pick("totp"), label: name), folder: folder,
                                        favourite: favourite, row: row.number))
        }
        return try ImportRules.result(records, [])
    }
}
