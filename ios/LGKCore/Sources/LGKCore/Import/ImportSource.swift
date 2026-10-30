import Foundation

/// The import sources the apps understand. Raw values are stable (vectors and settings use them).
public enum ImportFormat: String, CaseIterable, Sendable {
    case appleCSV, chrome, edge, brave, firefox, bitwarden, bitwardenEncrypted, onePassword1PUX, onePasswordCSV,
         lastPass, keePassKDBX, keePassXML, keePassCSV, protonPass, dashlane, cxf, generic

    /// The importer for this source (every format has one; optional so callers keep a single code path).
    public var importer: Importer.Type? {
        switch self {
        case .appleCSV, .chrome, .edge, .brave: return ChromiumCSV.self
        case .firefox: return FirefoxCSV.self
        case .bitwarden: return BitwardenJSON.self
        case .lastPass: return LastPassCSV.self
        case .onePasswordCSV: return OnePasswordCSV.self
        case .keePassCSV: return KeePassCSV.self
        case .keePassXML: return KeePassXML.self
        case .protonPass: return ProtonPassImport.self
        case .dashlane: return DashlaneImport.self
        case .generic: return GenericCSV.self
        case .bitwardenEncrypted: return BitwardenEncrypted.self
        case .onePassword1PUX: return OnePassword1PUX.self
        case .keePassKDBX: return KDBX.self
        case .cxf: return CXFImporter.self
        }
    }
}

public struct ImportOptions: Sendable {
    public var password: String?
    /// Column choice for `GenericCSV`; nil uses `GenericCSV.suggestMapping`.
    public var mapping: GenericCSVMapping?
    public init(password: String? = nil, mapping: GenericCSVMapping? = nil) {
        self.password = password; self.mapping = mapping
    }
}

public protocol Importer {
    static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult
}

/// A source item that was not imported, or a note about what was left out (the Windows diagnostics).
public struct ImportSkip: Sendable, Equatable {
    public var row: Int?
    public var message: String
    public init(row: Int? = nil, message: String) { self.row = row; self.message = message }
}

public struct ImportResult: Sendable, Equatable {
    public var candidates: [ImportCandidate]
    public var skipped: [ImportSkip]
    public init(candidates: [ImportCandidate] = [], skipped: [ImportSkip] = []) {
        self.candidates = candidates; self.skipped = skipped
    }
}

public enum ImportError: Error, Equatable, Sendable {
    case tooLarge, tooManyRows, unknownFormat, malformed(String), needsPassword, wrongPassword, unsupported(String)
    /// A KeePass database the password does not open: the Windows wording plus why a key file cannot help on the Mac.
    case wrongPasswordOrKeyFile(String)

    static var keyFileAdvice: String {
        " " + String(localized: "LocalGateKeys on this Mac opens KeePass databases with a password only; key files are not supported. If this database also uses a key file, remove it in KeePass (Database > Database Security) and try again.", bundle: .module)
    }

    /// The password was given but did not open the source (ask for it again).
    public var isWrongPassword: Bool {
        switch self {
        case .wrongPassword, .wrongPasswordOrKeyFile: return true
        default: return false
        }
    }

    /// The Windows (`localvault.importers`) wording.
    public var message: String {
        switch self {
        case .tooLarge: return String(localized: "Import source exceeds 8 MiB", bundle: .module)
        case .tooManyRows: return String(localized: "At most 5,000 records per import", bundle: .module)
        case .unknownFormat: return String(localized: "The file could not be recognised as a password-manager export; it may be damaged.", bundle: .module)
        case .malformed(let m), .unsupported(let m): return m
        case .needsPassword: return String(localized: "This export is password protected", bundle: .module)
        case .wrongPassword: return String(localized: "Wrong password or corrupted export (MAC mismatch)", bundle: .module)
        case .wrongPasswordOrKeyFile(let m): return m + Self.keyFileAdvice
        }
    }
}

public enum ImportSource {
    public static let maxSourceBytes = 8 * 1024 * 1024
    public static let maxArchiveBytes = 64 * 1024 * 1024
    public static let maxRecords = 5_000
    public static let maxCSVRows = 20_000
    public static let maxDiagnostics = 50

    /// Runs the importer for `format` (Windows `load_records`): diagnostics capped at 50 plus an "and N more" line.
    public static func candidates(from data: Data, format: ImportFormat, options: ImportOptions = ImportOptions()) throws -> ImportResult {
        guard let importer = format.importer else {
            throw ImportError.unsupported(String(localized: "This import format is not available yet", bundle: .module))
        }
        var result = try importer.candidates(from: data, options: options)
        result.skipped = capDiagnostics(result.skipped)
        return result
    }

    static func capDiagnostics(_ list: [ImportSkip]) -> [ImportSkip] {
        guard list.count > maxDiagnostics else { return list }
        let extra = list.count - maxDiagnostics
        return Array(list.prefix(maxDiagnostics))
            + [ImportSkip(message: String(localized: "...and \(extra) more messages.", bundle: .module))]
    }
}

// MARK: - Python string semantics

enum Py {
    static func isSpace(_ c: Unicode.Scalar) -> Bool { Origin.isPySpace(c) }
    static func strip(_ s: String) -> String { Normalise.pyStrip(s) }
    static func casefold(_ s: String) -> String { Casefold.fold(s) }
    static func split(_ s: String) -> [String] { Normalise.pySplit(s) }
    static func len(_ s: String) -> Int { s.unicodeScalars.count }
    static func scalars(_ a: some Sequence<Unicode.Scalar>) -> String { String(String.UnicodeScalarView(a)) }
    static func prefix(_ s: String, _ n: Int) -> String { scalars(s.unicodeScalars.prefix(n)) }
    static func suffix(_ s: String, _ n: Int) -> String { scalars(s.unicodeScalars.suffix(n)) }

    static func lstrip(_ s: String, _ chars: Set<Unicode.Scalar>) -> String {
        scalars(s.unicodeScalars.drop(while: { chars.contains($0) }))
    }
    static func rstrip(_ s: String, _ chars: Set<Unicode.Scalar>) -> String {
        var a = Array(s.unicodeScalars)
        while let l = a.last, chars.contains(l) { a.removeLast() }
        return scalars(a)
    }

    /// `str.splitlines()`.
    static func splitlines(_ s: String) -> [String] {
        var out: [String] = [], cur: [Unicode.Scalar] = []
        let u = Array(s.unicodeScalars)
        var i = 0
        while i < u.count {
            let c = u[i]
            switch c.value {
            case 0x0A, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029:
                out.append(scalars(cur)); cur = []
            case 0x0D:
                out.append(scalars(cur)); cur = []
                if i + 1 < u.count, u[i + 1] == "\n" { i += 1 }
            default: cur.append(c)
            }
            i += 1
        }
        if !cur.isEmpty { out.append(scalars(cur)) }
        return out
    }

    /// `str.partition(sep)` on the first occurrence.
    static func partition(_ s: String, _ sep: Character) -> (String, String)? {
        guard let i = s.firstIndex(of: sep) else { return nil }
        return (String(s[..<i]), String(s[s.index(after: i)...]))
    }

    static func isASCIIDigits(_ s: String) -> Bool { Normalise.isASCIIDigits(s) }

    /// `str.capitalize()`.
    static func capitalize(_ s: String) -> String {
        guard let f = s.unicodeScalars.first else { return "" }
        return String(f).uppercased() + scalars(s.unicodeScalars.dropFirst()).lowercased()
    }

    /// `f"{n:,}"`.
    static func thousands(_ n: Int) -> String {
        let digits = String(abs(n))
        var out = ""
        for (i, c) in digits.enumerated() {
            if i > 0, (digits.count - i) % 3 == 0 { out.append(",") }
            out.append(c)
        }
        return n < 0 ? "-" + out : out
    }

    /// `urllib.parse.quote(s, safe=safe)`.
    static func quote(_ s: String, safe: String) -> String {
        let keep = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~".utf8).union(safe.utf8)
        var out = ""
        for b in s.utf8 {
            if keep.contains(b) { out.append(Character(Unicode.Scalar(b))) }
            else { out += String(format: "%%%02X", b) }
        }
        return out
    }

    /// Python `int(text)` for plain decimal text (surrounding whitespace, a sign and `_` separators allowed).
    static func int(_ text: String) -> Int? {
        var t = strip(text)
        var negative = false
        if t.hasPrefix("+") || t.hasPrefix("-") { negative = t.hasPrefix("-"); t.removeFirst() }
        guard !t.isEmpty, !t.hasPrefix("_"), !t.hasSuffix("_"), !t.contains("__") else { return nil }
        t = t.replacingOccurrences(of: "_", with: "")
        guard isASCIIDigits(t), let v = Int(t) else { return nil }
        return negative ? -v : v
    }
}

// MARK: - Bounded text sources

enum ImportText {
    static func bounded(_ data: Data, limit: Int = ImportSource.maxSourceBytes) throws -> Data {
        guard data.count <= limit else {
            if limit == ImportSource.maxSourceBytes { throw ImportError.tooLarge }
            throw ImportError.malformed("Import source exceeds \(limit / (1024 * 1024)) MiB")
        }
        return data
    }

    /// Windows `decode_text`: UTF-16 with a BOM, UTF-8 (BOM stripped), else Windows-1252.
    static func decode(_ data: Data) throws -> String {
        let b = [UInt8](data)
        if b.starts(with: [0xFF, 0xFE]) || b.starts(with: [0xFE, 0xFF]) {
            let little = b[0] == 0xFF
            guard (b.count - 2) % 2 == 0 else { throw ImportError.malformed("Import source must be UTF-8 or UTF-16 text") }
            var units = [UInt16]()
            units.reserveCapacity((b.count - 2) / 2)
            var i = 2
            while i + 1 < b.count {
                units.append(little ? UInt16(b[i]) | UInt16(b[i + 1]) << 8 : UInt16(b[i]) << 8 | UInt16(b[i + 1]))
                i += 2
            }
            guard let s = Unicode.UTF16.decodeStrict(units) else {
                throw ImportError.malformed("Import source must be UTF-8 or UTF-16 text")
            }
            return s
        }
        let body = b.starts(with: [0xEF, 0xBB, 0xBF]) ? Array(b.dropFirst(3)) : b
        if let s = String(bytes: body, encoding: .utf8) { return s }
        // cp1252: five bytes are undefined and make Python's codec fail.
        if body.contains(where: { [0x81, 0x8D, 0x8F, 0x90, 0x9D].contains($0) }) {
            throw ImportError.malformed("Import source must be UTF-8 text")
        }
        return String(String.UnicodeScalarView(body.map { cp1252Scalar($0) }))
    }

    private static let cp1252High: [UInt32] = [
        0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
        0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
    ]

    static func cp1252Scalar(_ b: UInt8) -> Unicode.Scalar {
        if (0x80...0x9F).contains(b) { return Unicode.Scalar(cp1252High[Int(b) - 0x80])! }
        return Unicode.Scalar(b)
    }

    static func text(_ data: Data) throws -> String { try decode(bounded(data)) }
}

extension Unicode.UTF16 {
    static func decodeStrict(_ units: [UInt16]) -> String? {
        var it = units.makeIterator()
        var parser = Unicode.UTF16.ForwardParser()
        var out = String.UnicodeScalarView()
        while true {
            switch parser.parseScalar(from: &it) {
            case .valid(let e): out.append(Unicode.UTF16.decode(e))
            case .emptyInput: return String(out)
            case .error: return nil
            }
        }
    }
}

// MARK: - CSV (Python `csv` module, excel dialect, sniffed delimiter)

struct CSVRow {
    var number: Int
    var cells: [String]
    /// Keyed by `CSVTable.normalizeHeader`; the first column with a key wins.
    var values: [String: String]
    var extra: String?

    func pick(_ names: String...) -> String { pick(names) }
    func pick(_ names: [String]) -> String {
        for n in names {
            if let v = values[CSVTable.normalizeHeader(n)], !v.isEmpty { return v }
        }
        return ""
    }
    func get(_ key: String) -> String { values[key] ?? "" }
}

enum CSVTable {
    static let fieldLimit = 131_072

    static func normalizeHeader(_ name: String) -> String {
        var s = Py.strip(name.replacingOccurrences(of: "\u{FEFF}", with: ""))
        s = Py.casefold(s).replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        return Py.split(s).joined(separator: " ")
    }

    static func sniffDelimiter(_ text: String) -> Unicode.Scalar {
        let head = Py.splitlines(Py.prefix(text, 4096)).first ?? ""
        var best: Unicode.Scalar = ",", bestCount = 0
        for d in [",", ";", "\t"] as [Unicode.Scalar] {
            let n = head.unicodeScalars.filter { $0 == d }.count
            if n > bestCount { best = d; bestCount = n }
        }
        return best
    }

    /// Windows `read_csv_table`: (raw header, rows).
    static func read(_ text: String, maxRows: Int = ImportSource.maxCSVRows) throws -> (header: [String], rows: [CSVRow]) {
        if text.unicodeScalars.contains("\u{0}") { throw ImportError.malformed("CSV contains null characters") }
        var reader = Reader(text: text, delimiter: sniffDelimiter(text))
        guard let header = try reader.next(), header.contains(where: { !Py.strip($0).isEmpty }) else {
            throw ImportError.malformed("CSV has no header row")
        }
        let raw = header.map { Py.strip($0.replacingOccurrences(of: "\u{FEFF}", with: "")) }
        let keys = raw.map(normalizeHeader)
        var rows: [CSVRow] = []
        var number = 1
        while let values = try reader.next() {
            number += 1
            if values.isEmpty || values.allSatisfy({ Py.strip($0).isEmpty }) { continue }
            var dict: [String: String] = [:]
            for (k, v) in zip(keys, values) where !k.isEmpty && dict[k] == nil { dict[k] = v }
            let extra = values.count > keys.count ? values[keys.count...].joined(separator: "\n") : nil
            rows.append(CSVRow(number: number, cells: values, values: dict, extra: extra))
            if rows.count > maxRows { throw ImportError.malformed("At most \(Py.thousands(maxRows)) rows per CSV import") }
        }
        return (raw, rows)
    }

    static func header(_ text: String) throws -> [String] { try read(text).header }

    /// CPython `_csv.c` reader (strict off, doublequote on, no escape character).
    struct Reader {
        enum State { case startRecord, startField, inField, inQuoted, quoteInQuoted, eatCRNL }
        let u: [Unicode.Scalar]
        let delimiter: Unicode.Scalar
        var pos = 0
        var state = State.startRecord
        var fields: [String] = []
        var field: [Unicode.Scalar] = []
        init(text: String, delimiter: Unicode.Scalar) { u = Array(text.unicodeScalars); self.delimiter = delimiter }

        private mutating func save() { fields.append(Py.scalars(field)); field = [] }
        private mutating func add(_ c: Unicode.Scalar) throws {
            if field.count >= CSVTable.fieldLimit { throw ImportError.malformed("CSV is malformed") }
            field.append(c)
        }

        mutating func next() throws -> [String]? {
            fields = []; field = []; state = .startRecord
            repeat {
                guard pos < u.count else {
                    if !field.isEmpty || state == .inQuoted { save(); return fields }
                    return nil
                }
                // One line, terminator included (StringIO with newline="").
                var end = pos
                while end < u.count, u[end] != "\n", u[end] != "\r" { end += 1 }
                if end < u.count { end += (u[end] == "\r" && end + 1 < u.count && u[end + 1] == "\n") ? 2 : 1 }
                for i in pos..<end { try process(u[i]) }
                try process(nil)
                pos = end
            } while state != .startRecord
            return fields
        }

        private mutating func process(_ c: Unicode.Scalar?) throws {
            let nl = c == "\n" || c == "\r"
            switch state {
            case .startRecord:
                guard let c else { return }  // empty line
                if nl { state = .eatCRNL; return }
                state = .startField
                try process(c)
            case .startField:
                if c == nil || nl { save(); state = c == nil ? .startRecord : .eatCRNL }
                else if c == "\"" { state = .inQuoted }
                else if c == delimiter { save() }
                else { try add(c!); state = .inField }
            case .inField:
                if c == nil || nl { save(); state = c == nil ? .startRecord : .eatCRNL }
                else if c == delimiter { save(); state = .startField }
                else { try add(c!) }
            case .inQuoted:
                guard let c else { return }
                if c == "\"" { state = .quoteInQuoted } else { try add(c) }
            case .quoteInQuoted:
                if c == "\"" { try add("\""); state = .inQuoted }
                else if c == delimiter { save(); state = .startField }
                else if c == nil || nl { save(); state = c == nil ? .startRecord : .eatCRNL }
                else { try add(c!); state = .inField }
            case .eatCRNL:
                if nl { return }
                if c == nil { state = .startRecord; return }
                throw ImportError.malformed("CSV is malformed")
            }
        }
    }
}

// MARK: - Loosely typed JSON with key order (Python `json.loads`)

indirect enum PyJSON: Equatable {
    case null, bool(Bool), int(Int64), float(Double), string(String), array([PyJSON])
    case object([(String, PyJSON)])

    static func == (a: PyJSON, b: PyJSON) -> Bool {
        switch (a, b) {
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.int(x), .int(y)): return x == y
        case let (.float(x), .float(y)): return x == y
        case let (.string(x), .string(y)): return x == y
        case let (.array(x), .array(y)): return x == y
        case let (.object(x), .object(y)): return x.map(\.0) == y.map(\.0) && x.map(\.1) == y.map(\.1)
        default: return false
        }
    }

    subscript(key: String) -> PyJSON? {
        guard case .object(let pairs) = self else { return nil }
        return pairs.last(where: { $0.0 == key })?.1
    }

    func has(_ key: String) -> Bool { self[key] != nil }
    /// The first key in insertion order (`next(iter(d))`).
    var firstKey: String? {
        guard case .object(let pairs) = self else { return nil }
        return pairs.first?.0
    }
    var isObject: Bool { if case .object = self { return true }; return false }
    var objectValues: [PyJSON] {
        guard case .object(let pairs) = self else { return [] }
        var seen: [String: Int] = [:], out: [PyJSON] = []
        for (k, v) in pairs { if let i = seen[k] { out[i] = v } else { seen[k] = out.count; out.append(v) } }
        return out
    }
    /// `as_list`: the array, else empty.
    var list: [PyJSON] { if case .array(let a) = self { return a }; return [] }
    var isList: Bool { if case .array = self { return true }; return false }

    /// Python truthiness.
    var truthy: Bool {
        switch self {
        case .null: return false
        case .bool(let b): return b
        case .int(let i): return i != 0
        case .float(let f): return f != 0
        case .string(let s): return !s.isEmpty
        case .array(let a): return !a.isEmpty
        case .object(let o): return !o.isEmpty
        }
    }

    /// `value == n` in Python (`True == 1`, `1.0 == 1`).
    func equals(_ n: Int64) -> Bool {
        switch self {
        case .bool(let b): return (b ? 1 : 0) == n
        case .int(let i): return i == n
        case .float(let f): return f == Double(n)
        default: return false
        }
    }

    var isTrue: Bool { self == .bool(true) }

    /// `str(value)`.
    var str: String {
        switch self {
        case .string(let s): return s
        default: return repr
        }
    }

    /// `repr(value)` for the simple values exports contain.
    var repr: String {
        switch self {
        case .null: return "None"
        case .bool(let b): return b ? "True" : "False"
        case .int(let i): return String(i)
        case .float(let f): return PythonFloat.repr(f)
        case .string(let s):
            let quote = s.contains("'") && !s.contains("\"") ? "\"" : "'"
            var out = quote
            for c in s.unicodeScalars {
                switch c {
                case "\\": out += "\\\\"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                default:
                    if String(c) == quote { out += "\\" + quote }
                    else if c.value < 0x20 || c.value == 0x7F { out += String(format: "\\x%02x", c.value) }
                    else { out.unicodeScalars.append(c) }
                }
            }
            return out + quote
        case .array(let a): return "[" + a.map(\.repr).joined(separator: ", ") + "]"
        case .object:
            guard case .object(let pairs) = self else { return "" }
            return "{" + pairs.map { PyJSON.string($0.0).repr + ": " + $0.1.repr }.joined(separator: ", ") + "}"
        }
    }

    /// `str(x or "")`.
    static func text(_ v: PyJSON?) -> String { (v?.truthy ?? false) ? v!.str : "" }

    /// `_text`: "" for None, dicts and lists, else `str`.
    static func scalarText(_ v: PyJSON?) -> String {
        switch v {
        case nil, .null?, .array?, .object?: return ""
        case let x?: return x.str
        }
    }

    struct Failure: Error {}

    static func parse(_ text: String) throws -> PyJSON {
        var p = Parser(u: Array(text.unicodeScalars))
        p.ws()
        let v = try p.value(0)
        p.ws()
        guard p.i == p.u.count else { throw Failure() }
        return v
    }

    private struct Parser {
        let u: [Unicode.Scalar]
        var i = 0
        mutating func ws() { while i < u.count, [" ", "\t", "\n", "\r"].contains(u[i]) { i += 1 } }
        func peek() -> Unicode.Scalar? { i < u.count ? u[i] : nil }
        mutating func lit(_ s: String) -> Bool {
            let a = Array(s.unicodeScalars)
            guard i + a.count <= u.count, Array(u[i..<i + a.count]) == a else { return false }
            i += a.count; return true
        }
        mutating func value(_ depth: Int) throws -> PyJSON {
            guard depth < 900, let c = peek() else { throw Failure() }
            switch c {
            case "{":
                i += 1; ws()
                var pairs: [(String, PyJSON)] = []
                if peek() == "}" { i += 1; return .object(pairs) }
                while true {
                    ws()
                    guard peek() == "\"" else { throw Failure() }
                    let k = try string()
                    ws()
                    guard peek() == ":" else { throw Failure() }
                    i += 1; ws()
                    pairs.append((k, try value(depth + 1)))
                    ws()
                    guard let d = peek() else { throw Failure() }
                    i += 1
                    if d == "," { continue }
                    if d == "}" { return .object(pairs) }
                    throw Failure()
                }
            case "[":
                i += 1; ws()
                var items: [PyJSON] = []
                if peek() == "]" { i += 1; return .array(items) }
                while true {
                    ws()
                    items.append(try value(depth + 1))
                    ws()
                    guard let d = peek() else { throw Failure() }
                    i += 1
                    if d == "," { continue }
                    if d == "]" { return .array(items) }
                    throw Failure()
                }
            case "\"": return .string(try string())
            case "t": if lit("true") { return .bool(true) }; throw Failure()
            case "f": if lit("false") { return .bool(false) }; throw Failure()
            case "n": if lit("null") { return .null }; throw Failure()
            case "N": if lit("NaN") { return .float(.nan) }; throw Failure()
            case "I": if lit("Infinity") { return .float(.infinity) }; throw Failure()
            default:
                if c == "-", lit("-Infinity") { return .float(-.infinity) }
                return try number()
            }
        }
        mutating func number() throws -> PyJSON {
            let start = i
            var isFloat = false
            func digit(_ c: Unicode.Scalar?) -> Bool { c.map { ("0"..."9").contains($0) } ?? false }
            if peek() == "-" { i += 1 }
            if peek() == "0" { i += 1 } else if digit(peek()) { while digit(peek()) { i += 1 } } else { throw Failure() }
            if peek() == ".", i + 1 < u.count, digit(u[i + 1]) { isFloat = true; i += 1; while digit(peek()) { i += 1 } }
            if peek() == "e" || peek() == "E" {
                var j = i + 1
                if j < u.count, u[j] == "+" || u[j] == "-" { j += 1 }
                if j < u.count, digit(u[j]) { isFloat = true; i = j; while digit(peek()) { i += 1 } }
            }
            let text = Py.scalars(u[start..<i])
            if !isFloat, let n = Int64(text) { return .int(n) }
            guard let d = Double(text) else { throw Failure() }
            return .float(d)
        }
        mutating func hex4() throws -> UInt32 {
            guard i + 4 <= u.count, let v = UInt32(Py.scalars(u[i..<i + 4]), radix: 16) else { throw Failure() }
            i += 4; return v
        }
        mutating func string() throws -> String {
            i += 1
            var out = String.UnicodeScalarView()
            while true {
                guard let c = peek() else { throw Failure() }
                i += 1
                if c == "\"" { return String(out) }
                if c.value < 0x20 { throw Failure() }
                if c != "\\" { out.append(c); continue }
                guard let e = peek() else { throw Failure() }
                i += 1
                switch e {
                case "\"": out.append("\""); case "\\": out.append("\\"); case "/": out.append("/")
                case "b": out.append("\u{08}"); case "f": out.append("\u{0C}"); case "n": out.append("\n")
                case "r": out.append("\r"); case "t": out.append("\t")
                case "u":
                    var v = try hex4()
                    if (0xD800...0xDBFF).contains(v), peek() == "\\", i + 1 < u.count, u[i + 1] == "u" {
                        let save = i
                        i += 2
                        let lo = try hex4()
                        if (0xDC00...0xDFFF).contains(lo) { v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00) } else { i = save }
                    }
                    out.append(Unicode.Scalar(v) ?? "\u{FFFD}")
                default: throw Failure()
                }
            }
        }
    }
}

// MARK: - Record builder (Windows `ImportedRecord`)

struct ImportRecord {
    var kind = "login"
    var title = ""
    var username = ""
    var password = ""
    var urls: [String] = []
    var notes = ""
    var totp = ""
    var folder = ""
    var favourite = false
    var fields: [ImportCustomField] = []
    var created: Int64?
    var modified: Int64?
    var tags: [String] = []
    var identity: [String: String] = [:]
    var card: [String: String] = [:]
    var row: Int?

    static let cardKeys: Set<String> = ["cardholder", "number", "expiry", "cvv", "pin", "brand"]

    /// `__post_init__` for the card dictionary: known keys, stripped, non-empty.
    static func cleanCard(_ d: [String: String]) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in d where cardKeys.contains(k) && !v.isEmpty { out[k] = Py.strip(v) }
        return out
    }

    /// `add_custom_field`: skips blanks, at most 50 fields, names cut to 100 and values to 4,096 characters.
    mutating func addField(_ name: String, _ value: String?, hidden: Bool = false) {
        guard let value, !name.isEmpty, !value.isEmpty, fields.count < 50 else { return }
        fields.append(ImportCustomField(name: Py.prefix(name, 100), value: Py.prefix(value, 4096), hidden: hidden))
    }

    mutating func addField(_ name: String, _ value: PyJSON?, hidden: Bool = false) {
        guard let value, value != .null else { return }
        addField(name, value.str, hidden: hidden)
    }

    var candidate: ImportCandidate {
        let kindValue: ImportCandidate.Kind
        let urls = self.urls.filter { !$0.isEmpty }
        switch kind {
        case "login":
            kindValue = .login(LoginFields(url: urls.first ?? "", username: username, password: password, notes: notes,
                                           otpauth: totp.isEmpty ? nil : totp))
        case "card": kindValue = .card(CardFields(notes: notes, values: card))
        case "identity": kindValue = .identity(IdentityFields(notes: notes, values: identity))
        default: kindValue = .note(NoteFields(notes: notes))
        }
        var c = ImportCandidate(title: title, kind: kindValue, urls: urls, folder: folder, tags: tags,
                                customFields: fields.filter { !$0.name.isEmpty }, favourite: favourite,
                                created: created, modified: modified, sourceRow: row)
        if kind != "login", !totp.isEmpty { c.totp = totp }
        return c
    }
}

enum ImportRules {
    /// `enforce_record_limit` / `check_record_count`.
    static func checkCount(_ n: Int) throws { if n > ImportSource.maxRecords { throw ImportError.tooManyRows } }

    static func result(_ records: [ImportRecord], _ diagnostics: [String]) throws -> ImportResult {
        try checkCount(records.count)
        return ImportResult(candidates: records.map(\.candidate), skipped: diagnostics.map { ImportSkip(message: $0) })
    }

    /// `truthy`: "1", "true", "yes", "y", "on", "favorite".
    static func truthy(_ s: String) -> Bool {
        ["1", "true", "yes", "y", "on", "favorite"].contains(Py.casefold(Py.strip(s)))
    }

    /// `totp_uri_from_secret`.
    static func totpURI(_ secret: String, label: String = "", issuer: String = "", digits: Int = 6, period: Int = 30,
                        algorithm: String = "SHA1") -> String {
        let value = Py.strip(secret)
        if value.isEmpty { return "" }
        if Py.casefold(value).hasPrefix("otpauth://") { return value }
        let compact = Py.rstrip(Py.split(value.replacingOccurrences(of: "-", with: "")).joined().uppercased(), ["="])
        if compact.isEmpty { return "" }
        var query = ["secret=\(compact)"]
        if !issuer.isEmpty { query.append("issuer=\(Py.quote(issuer, safe: ""))") }
        if digits != 6 { query.append("digits=\(digits)") }
        if period != 30 { query.append("period=\(period)") }
        let alg = (algorithm.isEmpty ? "SHA1" : algorithm).uppercased()
            .replacingOccurrences(of: "HMAC-", with: "").replacingOccurrences(of: "-", with: "")
        if alg != "SHA1" { query.append("algorithm=\(alg)") }
        return "otpauth://totp/\(Py.quote(label.isEmpty ? "account" : label, safe: "@:"))?" + query.joined(separator: "&")
    }

    private static let months = ["january", "february", "march", "april", "may", "june", "july", "august",
                                 "september", "october", "november", "december"]

    /// `card_expiry`: `MM/YYYY`, or "" when unusable.
    static func cardExpiry(_ month: String, _ year: String = "") -> String {
        var m = Py.strip(month), y = Py.strip(year)
        if !m.isEmpty, y.isEmpty {
            let compact = m.replacingOccurrences(of: " ", with: "")
            if Py.isASCIIDigits(compact), Py.len(compact) == 6 {
                y = Py.prefix(compact, 4); m = Py.scalars(compact.unicodeScalars.dropFirst(4))
            } else {
                for sep in ["/", "-", ",", "."] as [Character] {
                    if let (first, second) = Py.partition(compact, sep) {
                        if Py.len(first) == 4, Py.isASCIIDigits(first) { y = first; m = second } else { m = first; y = second }
                        break
                    }
                }
            }
        }
        let key = Py.casefold(m)
        let number: Int
        if let i = months.firstIndex(of: key) { number = i + 1 }
        else if !Py.isASCIIDigits(key), let i = months.firstIndex(where: { Py.prefix($0, 3) == Py.prefix(key, 3) }),
                Set(months.map { Py.prefix($0, 3) }).contains(Py.prefix(key, 3)) { number = i + 1 }
        else if Py.isASCIIDigits(m), let v = Int(m) { number = v }
        else { return "" }
        guard (1...12).contains(number), Py.isASCIIDigits(y), [2, 4].contains(Py.len(y)), let yv = Int(y) else { return "" }
        let year = yv + (Py.len(y) == 2 ? 2000 : 0)
        return String(format: "%02d/%04d", number, year)
    }

    /// `host_title`: the URL's host name, else the URL itself.
    static func hostTitle(_ url: String) -> String {
        let s = Py.strip(url)
        return hostname(s) ?? s
    }

    /// `urlsplit(url).hostname` (nil when absent or the URL is refused).
    static func hostname(_ url: String) -> String? {
        var rest = Py.lstrip(url, Set((0...0x20).compactMap { Unicode.Scalar($0) }))
        rest = rest.replacingOccurrences(of: "\t", with: "").replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        if let colon = rest.firstIndex(of: ":"), colon != rest.startIndex {
            let scheme = rest[..<colon]
            let first = scheme.unicodeScalars.first!
            let schemeChars = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.".unicodeScalars)
            if first.isASCII, first.properties.isAlphabetic, scheme.unicodeScalars.allSatisfy({ schemeChars.contains($0) }) {
                rest = String(rest[rest.index(after: colon)...])
            }
        }
        guard rest.hasPrefix("//") else { return nil }
        let afterSlashes = rest.dropFirst(2)
        let netloc = String(afterSlashes.prefix(while: { !"/?#".contains($0) }))
        if netloc.contains("[") != netloc.contains("]") { return nil }  // ValueError: Invalid IPv6 URL
        let host = netloc.split(separator: "@", omittingEmptySubsequences: false).last.map(String.init) ?? ""
        var name: String
        if host.contains("[") {
            let after = host.split(separator: "[", maxSplits: 1, omittingEmptySubsequences: false)[1]
            name = String(after.split(separator: "]", maxSplits: 1, omittingEmptySubsequences: false)[0])
        } else {
            name = String(host.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)[0])
        }
        name = name.lowercased()
        return name.isEmpty ? nil : name
    }
}

// MARK: - Timestamps (Windows `parse_timestamp`)

enum ImportTime {
    static func parse(_ v: PyJSON?) -> Int64? {
        switch v {
        case nil, .null?, .bool?: return nil
        case .int(let i)?: return number(Double(i))
        case .float(let f)?: return number(f)
        case let x?: return parse(x.str)
        }
    }

    static func number(_ value: Double) -> Int64? {
        guard value.isFinite else { return nil }
        var n = value
        if n > 10_000_000_000 { n /= 1000 }
        guard n > 0, n < 9.2e18 else { return nil }
        return Int64(n)
    }

    static func parse(_ value: String) -> Int64? {
        let text = Py.strip(value)
        if text.isEmpty { return nil }
        let digits = Py.lstrip(text, ["-"])
        if Py.isASCIIDigits(digits) {
            guard Py.len(digits) <= 20 else { return nil }
            let dashes = Py.len(text) - Py.len(digits)
            guard dashes <= 1 else { return nil }
            guard let d = Double(text) else { return nil }
            return number(d)
        }
        return isoformat(text.replacingOccurrences(of: "Z", with: "+00:00")) ?? strptime(text)
    }

    static func epoch(_ y: Int, _ m: Int, _ d: Int, _ hh: Int, _ mm: Int, _ ss: Int) -> Int64? {
        guard (1...9999).contains(y), (1...12).contains(m), (0...23).contains(hh), (0...59).contains(mm), (0...59).contains(ss)
        else { return nil }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
        guard (1...dim).contains(d) else { return nil }
        // days from civil (Howard Hinnant)
        let yy = m <= 2 ? y - 1 : y
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = Int64(era * 146097 + doe - 719468)
        return days * 86400 + Int64(hh * 3600 + mm * 60 + ss)
    }

    private static func ints(_ u: ArraySlice<Unicode.Scalar>) -> Int? {
        let s = Py.scalars(u)
        return Py.isASCIIDigits(s) ? Int(s) : nil
    }

    /// `datetime.fromisoformat` (Python 3.12) for the shapes exports use, then `int(dt.timestamp())`.
    static func isoformat(_ text: String) -> Int64? {
        let u = Array(text.unicodeScalars)
        var y = 0, m = 0, d = 0, i = 0
        if u.count >= 10, u[4] == "-", u[7] == "-", let a = ints(u[0..<4]), let b = ints(u[5..<7]), let c = ints(u[8..<10]) {
            (y, m, d, i) = (a, b, c, 10)
        } else if u.count >= 8, let a = ints(u[0..<4]), let b = ints(u[4..<6]), let c = ints(u[6..<8]) {
            (y, m, d, i) = (a, b, c, 8)
            if u.count > 8, ("0"..."9").contains(u[8]) { return nil }
        } else { return nil }
        var hh = 0, mm = 0, ss = 0, frac = 0.0, offset = 0
        if i < u.count {
            i += 1  // any one separator character
            guard i + 2 <= u.count, let h = ints(u[i..<i + 2]) else { return nil }
            hh = h; i += 2
            let extended = i < u.count && u[i] == ":"
            func two() -> Int? {
                if extended { guard i < u.count, u[i] == ":" else { return nil }; i += 1 }
                guard i + 2 <= u.count, let v = ints(u[i..<i + 2]) else { return nil }
                i += 2; return v
            }
            if i < u.count, extended || ("0"..."9").contains(u[i]) {
                guard let v = two() else { return nil }; mm = v
                if i < u.count, extended ? u[i] == ":" : ("0"..."9").contains(u[i]) {
                    guard let s = two() else { return nil }; ss = s
                    if i < u.count, u[i] == "." || u[i] == "," {
                        i += 1
                        let start = i
                        while i < u.count, ("0"..."9").contains(u[i]) { i += 1 }
                        guard i > start else { return nil }
                        frac = Double("0." + Py.scalars(u[start..<i])) ?? 0
                    }
                }
            }
            if i < u.count {
                guard u[i] == "+" || u[i] == "-" else { return nil }
                let sign = u[i] == "-" ? -1 : 1
                i += 1
                guard i + 2 <= u.count, let oh = ints(u[i..<i + 2]) else { return nil }
                i += 2
                var om = 0, os = 0
                if i < u.count {
                    if u[i] == ":" { i += 1 }
                    guard i + 2 <= u.count, let v = ints(u[i..<i + 2]) else { return nil }
                    om = v; i += 2
                    if i < u.count {
                        if u[i] == ":" { i += 1 }
                        guard i + 2 <= u.count, let v = ints(u[i..<i + 2]) else { return nil }
                        os = v; i += 2
                        if i < u.count, u[i] == "." { i += 1; while i < u.count, ("0"..."9").contains(u[i]) { i += 1 } }
                    }
                }
                guard i == u.count, oh < 24, om < 60, os < 60 else { return nil }
                offset = sign * (oh * 3600 + om * 60 + os)
            }
        }
        guard let base = epoch(y, m, d, hh, mm, ss) else { return nil }
        let t = Double(base - Int64(offset)) + frac
        return Int64(t.rounded(.towardZero))
    }

    /// `strptime` with `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%d %H:%M:%S` or `%Y-%m-%d` (unpadded numbers allowed).
    static func strptime(_ text: String) -> Int64? {
        func nums(_ s: Substring, _ sep: Character, _ count: Int, maxLens: [Int]) -> [Int]? {
            let parts = s.split(separator: sep, omittingEmptySubsequences: false)
            guard parts.count == count else { return nil }
            var out = [Int]()
            for (p, l) in zip(parts, maxLens) {
                guard (1...l).contains(p.count), Py.isASCIIDigits(String(p)), let v = Int(p) else { return nil }
                out.append(v)
            }
            return out
        }
        for sep in ["T", " "] as [Character] {
            let halves = text.split(separator: sep, maxSplits: 1, omittingEmptySubsequences: false)
            if halves.count == 2, let d = nums(halves[0], "-", 3, maxLens: [4, 2, 2]),
               let t = nums(halves[1], ":", 3, maxLens: [2, 2, 2]) {
                return epoch(d[0], d[1], d[2], t[0], t[1], t[2])
            }
        }
        if let d = nums(Substring(text), "-", 3, maxLens: [4, 2, 2]) { return epoch(d[0], d[1], d[2], 0, 0, 0) }
        return nil
    }
}
