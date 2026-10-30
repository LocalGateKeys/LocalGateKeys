import Foundation

/// Column indices chosen for a CSV the app does not recognise.
public struct GenericCSVMapping: Sendable, Equatable {
    public var title: Int?
    public var url: Int?
    public var username: Int?
    public var password: Int?
    public var notes: Int?
    public var totp: Int?
    public init(title: Int? = nil, url: Int? = nil, username: Int? = nil, password: Int? = nil, notes: Int? = nil,
                totp: Int? = nil) {
        self.title = title; self.url = url; self.username = username; self.password = password
        self.notes = notes; self.totp = totp
    }
}

/// Any CSV, through a column mapping (Windows `load_generic_csv`).
public enum GenericCSV: Importer {
    /// Windows `FIELD_ALIASES`, in the order targets are guessed.
    static var aliases: [(WritableKeyPath<GenericCSVMapping, Int?>, [String])] { [
        (\.title, ["name", "title", "account", "label", "item"]),
        (\.url, ["url", "login uri", "web site", "website", "uri", "login url", "site", "address", "hostname"]),
        (\.username, ["username", "login username", "login name", "user name", "user", "login", "email"]),
        (\.password, ["password", "login password", "pass", "pwd", "secret"]),
        (\.notes, ["notes", "note", "comments", "comment", "extra", "notesplain"]),
        (\.totp, ["totp", "login totp", "otpauth", "otp", "one-time password", "otpsecret", "totp secret"]),
    ] }

    /// The raw header row, for the column chooser.
    public static func header(from data: Data) throws -> [String] {
        try CSVTable.header(ImportText.text(data))
    }

    /// Windows `guess_mapping`.
    public static func suggestMapping(header: [String]) -> GenericCSVMapping {
        let keys = header.map(CSVTable.normalizeHeader)
        var mapping = GenericCSVMapping()
        var used = Set<String>()
        for (path, names) in aliases {
            for alias in names {
                let key = CSVTable.normalizeHeader(alias)
                if let i = keys.firstIndex(of: key), !used.contains(key) {
                    mapping[keyPath: path] = i
                    used.insert(key)
                    break
                }
            }
        }
        return mapping
    }

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let (header, rows) = try CSVTable.read(ImportText.text(data))
        let m = options.mapping ?? suggestMapping(header: header)
        for i in [m.title, m.url, m.username, m.password, m.notes, m.totp].compactMap({ $0 }) where !header.indices.contains(i) {
            throw ImportError.malformed("Column \(i + 1) does not exist in the CSV header")
        }
        guard m.password != nil || m.notes != nil else {
            throw ImportError.malformed("CSV columns could not be mapped; choose the password column")
        }
        var records: [ImportRecord] = [], diagnostics: [String] = []
        for row in rows {
            func cell(_ i: Int?) -> String { guard let i, i < row.cells.count else { return "" }; return row.cells[i] }
            let url = Py.strip(cell(m.url)), username = cell(m.username), password = cell(m.password)
            let named = cell(m.title)
            let title = named.isEmpty ? ImportRules.hostTitle(url) : named
            let notes = cell(m.notes)
            if url.isEmpty, username.isEmpty, password.isEmpty {
                if !notes.isEmpty {
                    records.append(ImportRecord(kind: "note", title: title.isEmpty ? "Row \(row.number)" : title, notes: notes,
                                                row: row.number))
                } else {
                    diagnostics.append("Row \(row.number): empty row; skipped.")
                }
                continue
            }
            records.append(ImportRecord(kind: "login", title: title, username: username, password: password,
                                        urls: url.isEmpty ? [] : [url], notes: notes,
                                        totp: ImportRules.totpURI(cell(m.totp), label: title), row: row.number))
        }
        return try ImportRules.result(records, diagnostics)
    }
}
