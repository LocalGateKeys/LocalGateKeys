import Foundation

/// KeePass 2 (`Account,Login Name,...`) and KeePassXC (`Group,Title,...`) CSV exports.
public enum KeePassCSV: Importer {
    /// Windows `strip_root_group`.
    static func stripRootGroup(_ group: String) -> String {
        var parts = group.replacingOccurrences(of: "\\", with: "/").split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init).filter { !Py.strip($0).isEmpty }
        if let f = parts.first, ["root", "database", "passwords"].contains(Py.casefold(f)) { parts.removeFirst() }
        return parts.joined(separator: "/")
    }

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let (_, rows) = try CSVTable.read(ImportText.text(data))
        var records: [ImportRecord] = []
        for row in rows {
            let title = row.pick("title", "account"), url = row.pick("url", "web site")
            let username = row.pick("username", "login name"), password = row.pick("password")
            let notes = row.pick("notes", "comments"), folder = stripRootGroup(row.pick("group"))
            if url.isEmpty, username.isEmpty, password.isEmpty {
                records.append(ImportRecord(kind: "note", title: title, notes: notes, folder: folder, row: row.number))
                continue
            }
            records.append(ImportRecord(kind: "login", title: title.isEmpty ? url : title, username: username, password: password,
                                        urls: url.isEmpty ? [] : [url], notes: notes,
                                        totp: ImportRules.totpURI(row.pick("totp", "otp"), label: title), folder: folder,
                                        created: ImportTime.parse(row.pick("created")),
                                        modified: ImportTime.parse(row.pick("last modified")), row: row.number))
        }
        return try ImportRules.result(records, [])
    }
}
