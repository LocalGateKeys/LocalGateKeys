import Foundation

/// Bitwarden exports: unencrypted JSON and CSV (the password-protected JSON is opened by `BitwardenEncrypted`).
public enum BitwardenJSON: Importer {
    static let accountRestrictedMessage =
        "This Bitwarden export is encrypted with your Bitwarden account key, so only Bitwarden can open it. "
        + "In Bitwarden choose Export vault, then either File format 'JSON' (unencrypted) or "
        + "'.json (Encrypted)' with Export type 'Password protected', and enter that password here."

    private static let identityMap: [(String, String)] = [
        ("firstName", "given_name"), ("middleName", "middle_name"), ("lastName", "family_name"), ("company", "company"),
        ("email", "email"), ("phone", "phone"), ("address1", "address_line1"), ("address2", "address_line2"), ("city", "city"),
        ("state", "state"), ("postalCode", "postal_code"), ("country", "country"),
    ]
    private static let identitySensitive = [("ssn", "SSN"), ("passportNumber", "Passport number"), ("licenseNumber", "Licence number")]
    private static let identityExtra = [("title", "Title"), ("username", "Username"), ("address3", "Address 3")]

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let text = try ImportText.text(data)
        if Py.lstrip(text, ["\u{FEFF}", " ", "\t", "\r", "\n"]).hasPrefix("{") {
            return try json(text, password: options.password)
        }
        return try csv(text)
    }

    /// Windows `load_bitwarden_json`.
    static func json(_ text: String, password: String?) throws -> ImportResult {
        guard let doc = try? PyJSON.parse(text) else { throw ImportError.malformed("Invalid JSON") }
        guard doc.isObject else { throw ImportError.malformed("Expected a Bitwarden JSON export object") }
        if doc["encrypted"]?.isTrue == true, !(doc["passwordProtected"]?.truthy ?? false) {
            throw ImportError.malformed(accountRestrictedMessage)
        }
        if doc["encrypted"]?.truthy == true, doc.has("data") {
            if !(doc["passwordProtected"]?.truthy ?? false) { throw ImportError.malformed(accountRestrictedMessage) }
            guard let password, !password.isEmpty else { throw ImportError.needsPassword }
            return try records(BitwardenEncrypted.decrypt(doc, password: password))
        }
        return try records(doc)
    }

    /// Windows `records_from_document`.
    static func records(_ doc: PyJSON) throws -> ImportResult {
        guard case .array(let items)? = doc["items"] else {
            throw ImportError.malformed("Expected a Bitwarden JSON export with an 'items' list")
        }
        try ImportRules.checkCount(items.count)
        var folders: [String: String] = [:]
        for key in ["folders", "collections"] {
            for f in doc[key]?.list ?? [] where f.isObject {
                if let id = f["id"], id != .null { folders[id.str] = PyJSON.text(f["name"]) }
            }
        }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        var passkeys = 0
        for (offset, item) in items.enumerated() {
            let index = offset + 1
            guard item.isObject else { diagnostics.append("Item \(index): not an object; skipped."); continue }
            if item["deletedDate"]?.truthy == true {
                diagnostics.append("Item \(index): in the Bitwarden trash; skipped.")
                continue
            }
            var record: ImportRecord
            if let r = itemRecord(item, folders, row: index) {
                record = r
            } else {
                record = ImportRecord(kind: "note", title: PyJSON.text(item["name"]), notes: PyJSON.text(item["notes"]), row: index)
                record.addField("Bitwarden item type", item["type"])
                customFields(item, &record)
                diagnostics.append("Item \(index): unknown Bitwarden item type \((item["type"] ?? .null).repr); imported as a secure note.")
            }
            if let login = item["login"], login.isObject, login["fido2Credentials"]?.truthy == true { passkeys += 1 }
            records.append(record)
        }
        if passkeys > 0 {
            diagnostics.append("\(passkeys) login(s) have passkeys; Bitwarden does not export passkeys in a "
                               + "form another manager can use, so only the password was imported.")
        }
        return try ImportRules.result(records, diagnostics)
    }

    private static func customFields(_ item: PyJSON, _ record: inout ImportRecord) {
        for field in item["fields"]?.list ?? [] where field.isObject {
            let name = PyJSON.text(field["name"])
            guard var value = field["value"], value != .null else { continue }
            let kind = field["type"] ?? .int(0)
            if kind.equals(3) { continue }
            if kind.equals(2) { value = .string(Py.casefold(value.str) == "true" ? "true" : "false") }
            record.addField(name, value, hidden: kind.equals(1))
        }
    }

    private static func dict(_ v: PyJSON?) -> PyJSON { (v?.isObject ?? false) ? v! : .object([]) }

    static func itemRecord(_ item: PyJSON, _ folders: [String: String], row: Int) -> ImportRecord? {
        let type = item["type"] ?? .null
        let name = PyJSON.text(item["name"])
        var folder = ""
        if let id = item["folderId"], id.truthy { folder = folders[id.str] ?? "" }
        if folder.isEmpty {
            for c in item["collectionIds"]?.list ?? [] {
                folder = folders[c.str] ?? ""
                if !folder.isEmpty { break }
            }
        }
        var r = ImportRecord(title: name, notes: PyJSON.text(item["notes"]), folder: folder,
                             favourite: item["favorite"]?.truthy ?? false, created: ImportTime.parse(item["creationDate"]),
                             modified: ImportTime.parse(item["revisionDate"]), row: row)
        if type.equals(1) {
            let login = dict(item["login"])
            r.kind = "login"
            r.username = PyJSON.text(login["username"])
            r.password = PyJSON.text(login["password"])
            r.urls = (login["uris"]?.list ?? []).compactMap { u in u.isObject && (u["uri"]?.truthy ?? false) ? u["uri"]!.str : nil }
            r.totp = ImportRules.totpURI(PyJSON.text(login["totp"]), label: name)
        } else if type.equals(2) {
            r.kind = "note"
        } else if type.equals(3) {
            let card = dict(item["card"])
            r.kind = "card"
            r.card = ImportRecord.cleanCard([
                "cardholder": PyJSON.scalarText(card["cardholderName"]), "number": PyJSON.scalarText(card["number"]),
                "cvv": PyJSON.scalarText(card["code"]), "brand": PyJSON.scalarText(card["brand"]),
            ])
            let expiry = ImportRules.cardExpiry(PyJSON.scalarText(card["expMonth"]), PyJSON.scalarText(card["expYear"]))
            if !expiry.isEmpty {
                r.card["expiry"] = expiry
            } else {
                let raw = ["expMonth", "expYear"].filter { card[$0]?.truthy ?? false }.map { PyJSON.scalarText(card[$0]) }
                r.addField("Expiry", raw.joined(separator: "/"))
            }
        } else if type.equals(4) {
            let identity = dict(item["identity"])
            r.kind = "identity"
            for (key, target) in identityMap where identity[key]?.truthy ?? false { r.identity[target] = identity[key]!.str }
            let full = ["firstName", "middleName", "lastName"].filter { identity[$0]?.truthy ?? false }.map { identity[$0]!.str }
            if !full.isEmpty { r.identity["name"] = full.joined(separator: " ") }
            for (key, label) in identityExtra { r.addField(label, identity[key]) }
            for (key, label) in identitySensitive { r.addField(label, identity[key], hidden: true) }
        } else if type.equals(5) {
            let key = dict(item["sshKey"])
            r.kind = "note"
            r.addField("Bitwarden item type", "SSH key")
            r.addField("Private key", key["privateKey"], hidden: true)
            r.addField("Public key", key["publicKey"])
            r.addField("Fingerprint", key["keyFingerprint"])
        } else {
            return nil
        }
        customFields(item, &r)
        return r
    }

    /// Windows `load_bitwarden_csv` (also the layout the Windows app exports).
    static func csv(_ text: String) throws -> ImportResult {
        let (_, rows) = try CSVTable.read(text)
        var records: [ImportRecord] = [], diagnostics: [String] = []
        for row in rows {
            let typed = Py.casefold(row.pick("type"))
            let kind = typed.isEmpty ? "login" : typed
            let name = row.pick("name")
            var r = ImportRecord(kind: "note", title: name, notes: row.pick("notes"), folder: row.pick("folder"),
                                 favourite: ImportRules.truthy(row.pick("favorite")), row: row.number)
            if kind == "note" {
            } else if kind == "login" {
                r.kind = "login"
                r.username = row.pick("login_username")
                r.password = row.pick("login_password")
                r.urls = row.pick("login_uri").split(separator: ",", omittingEmptySubsequences: false)
                    .map { Py.strip(String($0)) }.filter { !$0.isEmpty }
                r.totp = ImportRules.totpURI(row.pick("login_totp"), label: name)
            } else {
                diagnostics.append("Row \(row.number): unsupported type \(PyJSON.string(kind).repr); imported as a note.")
            }
            for line in Py.splitlines(row.pick("fields")) {
                guard let (n, v) = Py.partition(line, ":") else { continue }
                r.addField(Py.strip(n), Py.strip(v))
            }
            records.append(r)
        }
        return try ImportRules.result(records, diagnostics)
    }
}

