import Foundation

/// Chrome / Edge / Brave, Firefox and Safari (Apple Passwords) CSV exports (Windows `load_browser_csv`).
public enum ChromiumCSV: Importer {
    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        try BrowserCSV.load(data)
    }
}

enum BrowserCSV {
    enum Layout { case chrome, firefox, safari }

    static func classify(_ header: [String]) -> Layout? {
        let keys = Set(header.map(CSVTable.normalizeHeader))
        if Set(["url", "username", "password", "httprealm", "formactionorigin"]).isSubset(of: keys) { return .firefox }
        if Set(["title", "url", "username", "password", "otpauth"]).isSubset(of: keys), keys.isDisjoint(with: ["favorite", "archived", "tags"]) {
            return .safari
        }
        if Set(["name", "url", "username", "password"]).isSubset(of: keys) { return .chrome }
        return nil
    }

    static func load(_ data: Data) throws -> ImportResult {
        let (header, rows) = try CSVTable.read(ImportText.text(data))
        let layout = classify(header) ?? .chrome
        var records: [ImportRecord] = [], diagnostics: [String] = []
        for row in rows {
            var url = Py.strip(row.pick("url"))
            if url.isEmpty, layout == .firefox { url = Py.strip(row.pick("formActionOrigin")) }
            let username = row.pick("username"), password = row.pick("password")
            if url.isEmpty, username.isEmpty, password.isEmpty {
                diagnostics.append("Row \(row.number): empty row; skipped.")
                continue
            }
            let name = row.pick("name", "title")
            let title = name.isEmpty ? ImportRules.hostTitle(url) : name
            var r = ImportRecord(kind: "login", title: title, username: username, password: password,
                                 urls: url.isEmpty ? [] : [url], notes: row.pick("note", "notes"),
                                 totp: ImportRules.totpURI(row.pick("otpauth", "totp"), label: title), row: row.number)
            if layout == .firefox {
                r.created = ImportTime.parse(row.pick("timeCreated"))
                r.modified = ImportTime.parse(row.pick("timePasswordChanged")) ?? ImportTime.parse(row.pick("timeLastUsed"))
            }
            records.append(r)
        }
        return try ImportRules.result(records, diagnostics)
    }
}
