import Foundation

/// 1Password 8 CSV (1Password 7 column names accepted too).
public enum OnePasswordCSV: Importer {
    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let (_, rows) = try CSVTable.read(ImportText.text(data))
        var records: [ImportRecord] = []
        for row in rows {
            let title = row.pick("title"), url = row.pick("url", "website", "urls")
            let username = row.pick("username"), password = row.pick("password")
            let notes = row.pick("notes", "notesplain")
            var r: ImportRecord
            if url.isEmpty, username.isEmpty, password.isEmpty {
                r = ImportRecord(kind: "note", title: title, notes: notes, row: row.number)
            } else {
                r = ImportRecord(kind: "login", title: title.isEmpty ? url : title, username: username, password: password,
                                 urls: url.isEmpty ? [] : [url], notes: notes,
                                 totp: ImportRules.totpURI(row.pick("otpauth", "one-time password", "totp"), label: title),
                                 row: row.number)
            }
            r.favourite = ImportRules.truthy(row.pick("favorite"))
            if ImportRules.truthy(row.pick("archived")) { r.folder = "Archive" }
            r.tags = row.pick("tags").replacingOccurrences(of: ";", with: ",").split(separator: ",", omittingEmptySubsequences: false)
                .map { Py.strip(String($0)) }.filter { !$0.isEmpty }
            records.append(r)
            try ImportRules.checkCount(records.count)
        }
        return try ImportRules.result(records, [])
    }
}
