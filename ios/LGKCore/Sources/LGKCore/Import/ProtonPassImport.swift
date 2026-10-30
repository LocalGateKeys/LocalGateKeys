import Foundation

/// Proton Pass exports: the unencrypted `data.json` and the CSV. The zip is opened through `ZipReader`.
public enum ProtonPassImport: Importer {
    static let encryptedMessage =
        "This Proton Pass export is PGP-encrypted, which LocalGateKeys cannot open. In Proton Pass choose "
        + "Settings > Export, turn off 'Encrypt with PGP' and import the resulting .zip (or export as CSV)."

    private static let identityMap: [(String, String)] = [
        ("fullName", "name"), ("firstName", "given_name"), ("middleName", "middle_name"), ("lastName", "family_name"),
        ("email", "email"), ("phoneNumber", "phone"), ("organization", "organization"), ("company", "company"),
        ("jobTitle", "job_title"), ("streetAddress", "address_line1"), ("city", "city"), ("stateOrProvince", "state"),
        ("zipOrPostalCode", "postal_code"), ("countryOrRegion", "country"), ("website", "website"),
    ]
    private static let identityHidden = [("socialSecurityNumber", "Social security number"),
                                         ("passportNumber", "Passport number"), ("licenseNumber", "Licence number")]
    private static let identityExtra = ["birthdate", "gender", "floor", "county", "secondPhoneNumber", "workPhoneNumber",
                                        "workEmail", "personalWebsite", "xHandle", "linkedin", "reddit", "facebook", "yahoo",
                                        "instagram"]
    private static let identitySections = ["extraPersonalDetails", "extraAddressDetails", "extraContactDetails", "extraWorkDetails"]
    private static let typeLabels = ["alias": "Email alias", "sshKey": "SSH key", "wifi": "Wi-Fi network", "custom": "Custom item"]

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let source = try ImportText.bounded(data, limit: ImportSource.maxArchiveBytes)
        if source.starts(with: [0x50, 0x4B]) { return try records(document(zipped(source))) }
        let asciiSpace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C]
        if Array(source.drop(while: { asciiSpace.contains($0) }).prefix(27)) == Array("-----BEGIN PGP MESSAGE-----".utf8) {
            throw ImportError.malformed(encryptedMessage)
        }
        let text = try ImportText.decode(source)
        if Py.lstrip(text, ["\u{FEFF}", " ", "\t", "\r", "\n"]).hasPrefix("{") {
            guard source.count <= 16 * 1024 * 1024 else { throw ImportError.malformed("data.json is too large") }
            guard let doc = try? PyJSON.parse(text) else { throw ImportError.malformed("Proton Pass data.json is not valid JSON") }
            guard doc.isObject else { throw ImportError.malformed("Proton Pass data.json is not an export object") }
            return try records(doc)
        }
        return try csv(ImportText.text(source))
    }

    static let maxDataBytes = 16 * 1024 * 1024

    /// Windows `read_data_json` for a zip: `Proton Pass/data.json`, else any `data.json`; PGP-encrypted exports refused.
    static func zipped(_ source: Data) throws -> Data {
        let corrupt = "The Proton Pass archive is corrupted or unsupported"
        let reader: ZipReader
        do { reader = try ZipReader(data: source, maxBytes: ImportSource.maxArchiveBytes, maxEntries: ZipReader.defaultMaxEntries) }
        catch let f as ZipReader.Failure { throw OnePassword1PUX.archiveError(f, corrupt: corrupt) }
        let entries = reader.entries()
        if entries.contains(where: { $0.name == "Proton Pass/data.pgp" || $0.name.hasSuffix(".pgp") }) {
            throw ImportError.malformed(encryptedMessage)
        }
        guard let e = reader.entry(named: "Proton Pass/data.json")
            ?? entries.first(where: { $0.name.split(separator: "/", omittingEmptySubsequences: false).last == "data.json" }) else {
            throw ImportError.malformed("The zip archive does not contain a Proton Pass data.json")
        }
        if e.uncompressedSize > maxDataBytes { throw ImportError.malformed("data.json is too large") }
        if e.isEncrypted || !(e.method == 0 || e.method == 8) {
            throw ImportError.malformed("data.json is encrypted or compressed in an unsupported way")
        }
        do { return try reader.read(e, limit: maxDataBytes) }
        catch ZipReader.Failure.tooLarge { throw ImportError.malformed("data.json is too large") }
        catch let f as ZipReader.Failure { throw OnePassword1PUX.archiveError(f, corrupt: corrupt) }
    }

    /// The JSON half of `read_data_json` (size, PGP armour, JSON object).
    static func document(_ raw: Data) throws -> PyJSON {
        if raw.count > maxDataBytes { throw ImportError.malformed("data.json is too large") }
        let asciiSpace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C]
        if Array(raw.drop(while: { asciiSpace.contains($0) }).prefix(27)) == Array("-----BEGIN PGP MESSAGE-----".utf8) {
            throw ImportError.malformed(encryptedMessage)
        }
        guard let doc = try? PyJSON.parse(ImportText.decode(raw)) else { throw ImportError.malformed("Proton Pass data.json is not valid JSON") }
        guard doc.isObject else { throw ImportError.malformed("Proton Pass data.json is not an export object") }
        return doc
    }

    private static func dict(_ v: PyJSON?) -> PyJSON { (v?.isObject ?? false) ? v! : .object([]) }
    private static func t(_ v: PyJSON?) -> String { PyJSON.scalarText(v) }

    static func extraFields(_ fields: PyJSON?, _ r: inout ImportRecord, title: String) {
        for field in fields?.list ?? [] where field.isObject {
            let named = t(field["fieldName"])
            let name = named.isEmpty ? "Field" : named
            let kind = Py.casefold(t(field["type"]))
            let data = dict(field["data"])
            if kind == "totp" {
                let uri = t(data["totpUri"])
                if !uri.isEmpty, r.totp.isEmpty, r.kind == "login" { r.totp = ImportRules.totpURI(uri, label: title) }
                else { r.addField(name, uri, hidden: true) }
                continue
            }
            if kind == "timestamp" { r.addField(name, t(data["timestamp"])); continue }
            r.addField(name, t(data["content"]), hidden: kind == "hidden")
        }
    }

    static func sections(_ list: PyJSON?, _ r: inout ImportRecord) {
        for s in list?.list ?? [] where s.isObject { extraFields(s["sectionFields"], &r, title: r.title) }
    }

    static func itemRecord(_ item: PyJSON, vault: String, row: Int) -> ImportRecord {
        let data = dict(item["data"]), metadata = dict(data["metadata"]), content = dict(data["content"])
        let kind = t(data["type"]), title = t(metadata["name"])
        var r = ImportRecord(kind: "note", title: title, notes: t(metadata["note"]), folder: vault,
                             favourite: item["pinned"]?.truthy ?? false, created: ImportTime.parse(item["createTime"]),
                             modified: ImportTime.parse(item["modifyTime"]), row: row)
        switch kind {
        case "login":
            let email = t(content["itemEmail"])
            var username = t(content["itemUsername"])
            if username.isEmpty { username = t(content["username"]) }
            r.kind = "login"
            r.username = username.isEmpty ? email : username
            r.password = t(content["password"])
            r.urls = (content["urls"]?.list ?? []).map(t).filter { !$0.isEmpty }
            r.totp = ImportRules.totpURI(t(content["totpUri"]), label: title)
            if !email.isEmpty, !username.isEmpty, email != username { r.addField("Email", email) }
            if content["passkeys"]?.truthy == true {
                r.addField("Passkeys", "This login had a passkey in Proton Pass; passkeys cannot be "
                           + "exported, so sign in with the password and register a new passkey.")
            }
        case "note":
            break
        case "creditCard":
            r.kind = "card"
            r.card = ImportRecord.cleanCard([
                "cardholder": t(content["cardholderName"]), "number": t(content["number"]),
                "cvv": t(content["verificationNumber"]), "pin": t(content["pin"]),
                "expiry": ImportRules.cardExpiry(t(content["expirationDate"])),
            ])
            if content["expirationDate"]?.truthy == true, (r.card["expiry"] ?? "").isEmpty {
                r.addField("Expiry", t(content["expirationDate"]))
            }
        case "identity":
            r.kind = "identity"
            for (key, target) in identityMap where !t(content[key]).isEmpty { r.identity[target] = t(content[key]) }
            if r.identity["name"] == nil {
                let full = Py.split(["given_name", "middle_name", "family_name"].map { r.identity[$0] ?? "" }.joined(separator: " "))
                if !full.isEmpty { r.identity["name"] = full.joined(separator: " ") }
            }
            for (key, label) in identityHidden { r.addField(label, t(content[key]), hidden: true) }
            for key in identityExtra { r.addField(key, t(content[key])) }
            for key in identitySections { extraFields(content[key], &r, title: title) }
            sections(content["extraSections"], &r)
        default:
            r.addField("Proton Pass item type", typeLabels[kind] ?? (kind.isEmpty ? "unknown" : kind))
            if kind == "alias" {
                r.addField("Alias address", t(item["aliasEmail"]))
            } else if kind == "sshKey" {
                r.addField("Private key", t(content["privateKey"]), hidden: true)
                r.addField("Public key", t(content["publicKey"]))
            } else if kind == "wifi" {
                r.addField("Network name (SSID)", t(content["ssid"]))
                r.addField("Wi-Fi password", t(content["password"]), hidden: true)
                r.addField("Security", t(content["security"]))
            }
            sections(content["sections"], &r)
        }
        extraFields(data["extraFields"], &r, title: title)
        return r
    }

    /// Windows `records_from_document`.
    static func records(_ doc: PyJSON) throws -> ImportResult {
        if doc["encrypted"]?.isTrue == true { throw ImportError.malformed(encryptedMessage) }
        guard let vaults = doc["vaults"], vaults.isObject else {
            throw ImportError.malformed("Proton Pass export has no 'vaults' object")
        }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        var trashed = 0, index = 0
        for vault in vaults.objectValues where vault.isObject {
            let name = t(vault["name"])
            for item in vault["items"]?.list ?? [] {
                index += 1
                try ImportRules.checkCount(index)
                guard item.isObject else { diagnostics.append("Item \(index): not an object; skipped."); continue }
                if item["state"]?.equals(2) == true { trashed += 1; continue }
                records.append(itemRecord(item, vault: name, row: index))
            }
        }
        if trashed > 0 { diagnostics.append("\(trashed) items in the Proton Pass trash were not imported.") }
        return try ImportRules.result(records, diagnostics)
    }

    /// Windows `load_protonpass_csv`.
    static func csv(_ text: String) throws -> ImportResult {
        let (_, rows) = try CSVTable.read(text)
        var records: [ImportRecord] = [], diagnostics: [String] = []
        for row in rows {
            let typed = Py.casefold(row.pick("type"))
            let kind = typed.isEmpty ? "login" : typed
            let title = row.pick("name"), email = row.pick("email")
            let named = row.pick("username")
            let username = named.isEmpty ? email : named
            var r = ImportRecord(kind: "note", title: title, notes: row.pick("note"), folder: row.pick("vault"),
                                 created: ImportTime.parse(row.pick("createTime")),
                                 modified: ImportTime.parse(row.pick("modifyTime")), row: row.number)
            if kind == "login" {
                r.kind = "login"
                r.username = username
                r.password = row.pick("password")
                r.urls = row.pick("url").split(separator: ",", omittingEmptySubsequences: false)
                    .map { Py.strip(String($0)) }.filter { !$0.isEmpty }
                r.totp = ImportRules.totpURI(row.pick("totp"), label: title)
                if !email.isEmpty, email != username { r.addField("Email", email) }
            } else if kind != "note" {
                r.addField("Proton Pass item type", typeLabels[kind] ?? kind)
                r.addField("Email", email)
                r.addField("Username", row.pick("username"))
                r.addField("Password", row.pick("password"), hidden: true)
                r.addField("URL", row.pick("url"))
                if kind == "creditcard" || kind == "identity" {
                    diagnostics.append("Row \(row.number): Proton Pass CSV does not include \(kind) details; use the JSON export "
                                       + "to import cards and identities fully.")
                }
            }
            records.append(r)
            try ImportRules.checkCount(records.count)
        }
        return try ImportRules.result(records, diagnostics)
    }
}
