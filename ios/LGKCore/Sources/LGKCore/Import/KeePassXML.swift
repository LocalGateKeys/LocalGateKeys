import Foundation

/// Unencrypted KeePass 2 XML export (Windows `load_keepass_xml`). The entry mapping is shared with the KDBX reader.
public enum KeePassXML: Importer {
    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let source = try ImportText.bounded(data)
        let root = try KeePassTree.parse(source)
        try KeePassTree.unprotect(root)
        return try KeePassTree.records(root)
    }
}

/// A minimal ElementTree: tag, attributes, `.text` (before the first child) and children.
final class XMLNode {
    let tag: String
    let attributes: [String: String]
    var text = ""
    var children: [XMLNode] = []
    init(tag: String, attributes: [String: String]) { self.tag = tag; self.attributes = attributes }

    func find(_ tag: String) -> XMLNode? { children.first { $0.tag == tag } }
    func findAll(_ tag: String) -> [XMLNode] { children.filter { $0.tag == tag } }
    /// `findtext`: nil when there is no such child.
    func findText(_ tag: String) -> String? { find(tag)?.text }
    func iter(_ tag: String, _ body: (XMLNode) throws -> Void) rethrows {
        if self.tag == tag { try body(self) }
        for c in children { try c.iter(tag, body) }
    }
}

enum KeePassTree {
    static let maxElements = 4_000_000
    static let maxHistoryEntries = 20 * ImportSource.maxRecords
    static let maxProtectedValueBytes = 1024 * 1024
    static let maxProtectedTotalBytes = 64 * 1024 * 1024
    static let epochOffset: Int64 = 62_135_596_800
    static let standardKeys: Set<String> = ["Title", "UserName", "Password", "URL", "Notes"]
    static let totpKeys: Set<String> = ["otp", "totp seed", "totp settings", "timeotp-secret-base32", "timeotp-secret",
                                        "timeotp-secret-hex", "timeotp-length", "timeotp-period", "timeotp-algorithm"]

    private final class Builder: NSObject, XMLParserDelegate {
        var stack: [XMLNode] = []
        var root: XMLNode?
        var failure: ImportError?
        var elements = 0, entries = 0, historyEntries = 0, historyDepth = 0
        /// Whether the open element has had a child yet (text after a child is ElementTree `tail`, not `text`).
        var sawChild: [Bool] = []

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            elements += 1
            if elements > KeePassTree.maxElements { return stop(parser, "Database XML has too many elements to import") }
            if name == "History" { historyDepth += 1 }
            else if name == "Entry" {
                if historyDepth > 0 {
                    historyEntries += 1
                    if historyEntries > KeePassTree.maxHistoryEntries {
                        return stop(parser, "Database has too many historical entry versions to import")
                    }
                } else {
                    entries += 1
                    if entries > ImportSource.maxRecords { return stop(parser, "At most 5,000 records per import") }
                }
            }
            let node = XMLNode(tag: name, attributes: attributes)
            if let parent = stack.last { parent.children.append(node); sawChild[sawChild.count - 1] = true } else { root = node }
            stack.append(node)
            sawChild.append(false)
        }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            if name == "History", historyDepth > 0 { historyDepth -= 1 }
            stack.removeLast()
            sawChild.removeLast()
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if let node = stack.last, sawChild.last == false { node.text += string }
        }

        func parser(_ parser: XMLParser, foundCDATA block: Data) {
            if let node = stack.last, sawChild.last == false { node.text += String(decoding: block, as: UTF8.self) }
        }

        func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) { doctype(parser) }
        func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
            doctype(parser)
        }
        func parser(_ parser: XMLParser, foundNotationDeclarationWithName name: String, publicID: String?, systemID: String?) {
            doctype(parser)
        }
        func parser(_ parser: XMLParser, foundUnparsedEntityDeclarationWithName name: String, publicID: String?,
                    systemID: String?, notationName: String?) { doctype(parser) }

        func doctype(_ parser: XMLParser) { stop(parser, "Database XML contains a DOCTYPE declaration and was rejected") }

        func stop(_ parser: XMLParser, _ message: String) {
            if failure == nil { failure = .malformed(message) }
            parser.abortParsing()
        }
    }

    /// Parses untrusted XML, refusing any DOCTYPE (KeePass never writes one).
    static func parse(_ data: Data) throws -> XMLNode {
        for encoding in [String.Encoding.utf8, .utf16LittleEndian, .utf16BigEndian] {
            if let marker = "<!DOCTYPE".data(using: encoding), data.range(of: marker) != nil {
                throw ImportError.malformed("Database XML contains a DOCTYPE declaration and was rejected")
            }
        }
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        let builder = Builder()
        parser.delegate = builder
        let ok = parser.parse()
        if let failure = builder.failure { throw failure }
        guard ok, let root = builder.root else { throw ImportError.malformed("Database XML is malformed") }
        guard root.tag == "KeePassFile" else { throw ImportError.malformed("Database XML is not a KeePassFile document") }
        return root
    }

    /// Windows `_unprotect_tree` without an inner stream (XML export): protected values are plain Base64.
    static func unprotect(_ root: XMLNode) throws {
        var none: InnerStream?
        try unprotect(root, stream: &none)
    }

    /// Windows `_unprotect_tree`: protected values decrypted in document order (history included), each bounded and the
    /// total held to 64 MiB (4 MiB for the Salsa20 and ARC4 streams).
    static func unprotect(_ root: XMLNode, stream: inout InnerStream?) throws {
        var total = 0
        let budget = stream?.isSlow == true ? KDBX.maxSlowStreamTotalBytes : maxProtectedTotalBytes
        try root.iter("Value") { value in
            guard Py.casefold(value.attributes["Protected"] ?? "") == "true" else { return }
            let text = Py.strip(value.text)
            if text.isEmpty { value.text = ""; return }
            let size = Py.len(text) / 4 * 3
            total += size
            if size > maxProtectedValueBytes + 3 { throw ImportError.malformed("A protected value in this database is too large to import") }
            if total > budget { throw ImportError.malformed("The protected values in this database are too large to import") }
            guard let raw = Data(base64Encoded: text) else { throw ImportError.malformed("Protected value is not valid Base64") }
            guard stream != nil else { value.text = String(decoding: raw, as: UTF8.self); return }
            var bytes = [UInt8](raw)
            stream!.process(&bytes)
            guard let plain = String(bytes: bytes, encoding: .utf8) else {
                throw ImportError.malformed("Protected value did not decrypt to text")
            }
            value.text = plain
        }
    }

    struct Entry {
        var uuid = ""
        var strings: [(String, String)] = []
        var protected: Set<String> = []
        var created: Int64?
        var modified: Int64?
        var tags: [String] = []
        var history = 0
        var binaries = 0
        var path: [String] = []
        func string(_ key: String) -> String { strings.first { $0.0 == key }?.1 ?? "" }
    }

    struct Group {
        var uuid = ""
        var entries: [Entry] = []
        var groups: [Group] = []
    }

    /// `_parse_time`: Base64 little-endian seconds since 0001-01-01 (KDBX 4) or ISO text.
    static func time(_ text: String?) -> Int64? {
        guard let text, !text.isEmpty else { return nil }
        let s = Py.strip(text)
        if s.contains(":") || Py.scalars(s.unicodeScalars.dropFirst()).contains("-") { return ImportTime.parse(s) }
        guard let raw = Data(base64Encoded: s), raw.count == 8 else { return nil }
        let v = raw.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
        return Int64(bitPattern: v) &- epochOffset
    }

    static func entry(_ node: XMLNode, _ path: [String]) -> Entry {
        var e = Entry(uuid: Py.strip(node.findText("UUID") ?? ""), path: path)
        for s in node.findAll("String") {
            let key = s.findText("Key") ?? ""
            let valueNode = s.find("Value")
            let value = valueNode?.text ?? ""
            if let v = valueNode, Py.casefold(v.attributes["Protected"] ?? "") == "true"
                || Py.casefold(v.attributes["ProtectInMemory"] ?? "") == "true" {
                e.protected.insert(key)
            }
            if let i = e.strings.firstIndex(where: { $0.0 == key }) { e.strings[i].1 = value } else { e.strings.append((key, value)) }
        }
        if let times = node.find("Times") {
            e.created = time(times.findText("CreationTime"))
            e.modified = time(times.findText("LastModificationTime"))
        }
        let tags = node.findText("Tags") ?? ""
        e.tags = tags.split(whereSeparator: { $0 == ";" || $0 == "," }).map { Py.strip(String($0)) }.filter { !$0.isEmpty }
        e.binaries = node.findAll("Binary").count
        e.history = node.find("History")?.findAll("Entry").count ?? 0
        return e
    }

    static func group(_ node: XMLNode, _ path: [String], isRoot: Bool) -> Group {
        let name = Py.strip(node.findText("Name") ?? "")
        let own = isRoot ? path : path + [name]
        return Group(uuid: Py.strip(node.findText("UUID") ?? ""), entries: node.findAll("Entry").map { entry($0, own) },
                     groups: node.findAll("Group").map { group($0, own, isRoot: false) })
    }

    static func walk(_ g: Group, bin: String, inBin: Bool, includeBin: Bool, _ out: inout [Entry]) {
        let inside = inBin || (!bin.isEmpty && g.uuid == bin)
        if inside, !includeBin { return }
        out += g.entries
        for c in g.groups { walk(c, bin: bin, inBin: inside, includeBin: includeBin, &out) }
    }

    /// `_totp_from_strings`: (otpauth URI, consumed keys).
    static func totp(_ strings: [(String, String)], title: String) -> (String, Set<String>) {
        var lowered: [String: String] = [:]
        for (k, _) in strings { lowered[Py.casefold(k)] = k }
        func value(_ k: String) -> String { strings.last { $0.0 == k }?.1 ?? "" }
        var consumed = Set<String>()
        if let key = lowered["otp"], !Py.strip(value(key)).isEmpty {
            let v = Py.strip(value(key))
            consumed.insert(key)
            if Py.casefold(v).hasPrefix("otpauth://") { return (v, consumed) }
            if Py.casefold(v).contains("key=") {
                var raw: [(String, String)] = []
                for part in v.split(separator: "&", omittingEmptySubsequences: false) {
                    guard let (n, val) = Py.partition(String(part), "="), !val.isEmpty else { continue }
                    let name = unquotePlus(n)
                    if !raw.contains(where: { $0.0 == name }) { raw.append((name, unquotePlus(val))) }
                }
                var params: [String: String] = [:]
                for (n, val) in raw { params[Py.casefold(n)] = val }
                if let secret = params["key"], !secret.isEmpty {
                    func number(_ k: String, _ d: Int) -> Int? { params[k].map { Py.int($0) } ?? d }
                    if let digits = number("size", 6), let period = number("step", 30) {
                        return (ImportRules.totpURI(secret, label: title, digits: digits, period: period,
                                                    algorithm: params["otphashmode"] ?? "SHA1"), consumed)
                    }
                }
            }
            return (ImportRules.totpURI(v, label: title), consumed)
        }
        if let key = lowered["totp seed"], !Py.strip(value(key)).isEmpty {
            consumed.insert(key)
            var digits = 6, period = 30
            if let s = lowered["totp settings"] {
                consumed.insert(s)
                let parts = value(s).split(separator: ";", omittingEmptySubsequences: false).map(String.init)
                let p0 = parts.first.map { Py.strip($0).isEmpty ? "30" : $0 } ?? "30"
                if let p = Py.int(p0) {
                    period = p
                    digits = parts.count > 1 && Py.isASCIIDigits(Py.strip(parts[1])) ? (Py.int(parts[1]) ?? 6) : 6
                } else { digits = 6; period = 30 }
            }
            return (ImportRules.totpURI(value(key), label: title, digits: digits, period: period), consumed)
        }
        if let key = lowered["timeotp-secret-base32"], !Py.strip(value(key)).isEmpty {
            consumed.insert(key)
            var digits = 6, period = 30, algorithm = "SHA1"
            for name in ["timeotp-length", "timeotp-period", "timeotp-algorithm"] {
                guard let k = lowered[name] else { continue }
                consumed.insert(k)
                let v = Py.strip(value(k))
                if name == "timeotp-length", Py.isASCIIDigits(v) { digits = Int(v) ?? 6 }
                else if name == "timeotp-period", Py.isASCIIDigits(v) { period = Int(v) ?? 30 }
                else if name == "timeotp-algorithm", !v.isEmpty {
                    algorithm = v.uppercased().replacingOccurrences(of: "HMAC-", with: "").replacingOccurrences(of: "-", with: "")
                }
            }
            return (ImportRules.totpURI(value(key), label: title, digits: digits, period: period, algorithm: algorithm), consumed)
        }
        for name in ["timeotp-secret", "timeotp-secret-hex"] { if let k = lowered[name] { consumed.insert(k) } }
        return ("", consumed)
    }

    static func unquotePlus(_ s: String) -> String {
        let spaced = s.replacingOccurrences(of: "+", with: " ")
        return spaced.removingPercentEncoding ?? spaced
    }

    static func record(_ e: Entry, row: Int) -> ImportRecord {
        let title = e.string("Title")
        let (uri, consumed) = totp(e.strings, title: title)
        var fields: [ImportCustomField] = []
        for (key, value) in e.strings {
            if standardKeys.contains(key) || consumed.contains(key) || totpKeys.contains(Py.casefold(key)) || value.isEmpty { continue }
            fields.append(ImportCustomField(name: key, value: value, hidden: e.protected.contains(key)))
        }
        let username = e.string("UserName"), password = e.string("Password"), url = e.string("URL"), notes = e.string("Notes")
        let kind = username.isEmpty && password.isEmpty && url.isEmpty && uri.isEmpty && !notes.isEmpty ? "note" : "login"
        return ImportRecord(kind: kind, title: title, username: username, password: password, urls: url.isEmpty ? [] : [url],
                            notes: notes, totp: uri, folder: e.path.joined(separator: "/"), fields: fields,
                            created: e.created, modified: e.modified, tags: e.tags, row: row)
    }

    /// `_database_from_tree` + `records_from_database`.
    static func records(_ root: XMLNode) throws -> ImportResult {
        var meta: [String: String] = [:]
        for child in root.find("Meta")?.children ?? [] where !child.text.isEmpty && child.children.isEmpty {
            meta[child.tag] = Py.strip(child.text)
        }
        guard let rootGroup = root.find("Root")?.find("Group") else { throw ImportError.malformed("Database XML has no root group") }
        let tree = group(rootGroup, [], isRoot: true)
        let bin = meta["RecycleBinUUID"] ?? ""
        var live: [Entry] = [], all: [Entry] = []
        walk(tree, bin: bin, inBin: false, includeBin: false, &live)
        walk(tree, bin: bin, inBin: false, includeBin: true, &all)
        var records: [ImportRecord] = []
        var history = 0, withFiles = 0
        for (i, e) in live.enumerated() {
            try ImportRules.checkCount(i + 1)
            history += e.history
            if e.binaries > 0 { withFiles += 1 }
            records.append(record(e, row: i + 1))
        }
        var diagnostics: [String] = []
        let recycled = all.count - live.count
        if recycled > 0 { diagnostics.append("\(recycled) entries in the KeePass Recycle Bin were not imported.") }
        if history > 0 { diagnostics.append("\(history) historical entry versions were not imported (only current values are kept).") }
        if withFiles > 0 { diagnostics.append("\(withFiles) entries have attachments that were not imported.") }
        return try ImportRules.result(records, diagnostics)
    }
}
