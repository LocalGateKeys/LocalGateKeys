import Crypto
import Foundation

/// The file looks like a KeePass XML key file but is not a valid one, or its key is not 32 bytes. Never carries
/// key material.
public struct KeyFileError: Error, Equatable, Sendable {
    public let message: String
    init(_ message: String) { self.message = message }
    static let doctype = KeyFileError("Key file contains a DOCTYPE and was rejected")
    static let malformed = KeyFileError("Key file XML is malformed")
}

/// KeePass key files (docs/formats/COMPOSITE_KEY_V1.md §1.1; Windows `src/localvault/keyfile.py`, Android
/// `KeyFile.kt`), tried in order:
///
/// 1. XML (the file trimmed of ASCII space/tab/CR/LF starts with `<?xml` or `<KeyFile`): `Meta/Version` starting with
///    "2" means hex data with an optional `Hash` check, anything else Base64 data. A DOCTYPE or malformed XML is refused.
/// 2. exactly 32 bytes: the file itself;
/// 3. exactly 64 bytes, all hex digits: the decoded hex;
/// 4. anything else: SHA-256 of the whole file.
///
/// Kept on purpose as in Windows and Android: an XML-looking file that does not parse is refused (KeePass would hash
/// it), and a file starting with a UTF-8 BOM misses rule 1 and is hashed.
public enum KeyFile {
    public static let keySize = 32
    /// Larger than any real key file (the Windows app's `MAX_KEYFILE_BYTES`); a reader stops after this many bytes.
    public static let maxBytes = 64 * 1024 * 1024
    static let maxElements = 10_000

    /// The 32-byte key of a key file used as an unlock factor; XML data of another length is refused.
    public static func key(from data: Data) throws -> [UInt8] {
        var key = try keyMaterial(data)
        guard key.count == keySize else {
            wipe(&key)
            throw KeyFileError("Key file data must be 32 bytes")
        }
        return key
    }

    /// The key material under KeePass rules; XML data may have any length (an importer's view).
    static func keyMaterial(_ data: Data) throws -> [UInt8] {
        var bytes = [UInt8](data)
        defer { wipe(&bytes) }
        var start = 0, end = bytes.count
        while start < end, isWhitespace(bytes[start]) { start += 1 }
        while end > start, isWhitespace(bytes[end - 1]) { end -= 1 }
        // Prefix checks by index: no named slice keeps a second reference to the buffer that the wipe must reach.
        func hasPrefix(_ prefix: String) -> Bool {
            let p = Array(prefix.utf8)
            return end - start >= p.count && (0..<p.count).allSatisfy { bytes[start + $0] == p[$0] }
        }
        if hasPrefix("<?xml") || hasPrefix("<KeyFile") {
            var text = Array(bytes[start..<end])
            defer { wipe(&text) }
            return try xmlKey(text)
        }
        if bytes.count == keySize { return Array(bytes) }
        if bytes.count == 2 * keySize, bytes.allSatisfy(isHexDigit) { return hexDecode(bytes) }
        return Array(SHA256.hash(data: bytes))
    }

    /// A KeePass XML 2.0 key file for `key` in the layout KeePass and KeePassXC write (LF line ends).
    public static func keepassXMLv2(key: [UInt8]) throws -> Data {
        guard key.count == keySize else { throw KeyFileError("key must be 32 bytes") }
        let hex = lowerHex(key).uppercased()
        let groups = stride(from: 0, to: hex.count, by: 8).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 8)])
        }
        let lines = stride(from: 0, to: groups.count, by: 4).map { "\n            " + groups[$0..<min($0 + 4, groups.count)].joined(separator: " ") }
            .joined()
        let checksum = lowerHex(Array(SHA256.hash(data: key)).prefix(4)).uppercased()
        let text = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<KeyFile>",
            "    <Meta>",
            "        <Version>2.0</Version>",
            "    </Meta>",
            "    <Key>",
            "        <Data Hash=\"\(checksum)\">\(lines)",
            "        </Data>",
            "    </Key>",
            "</KeyFile>",
            "",
        ].joined(separator: "\n")
        return Data(text.utf8)
    }

    /// A new random KeePass XML 2.0 key file ("Create key file"); it also opens in KeePass and KeePassXC.
    public static func newKeepassXMLv2(random: any RandomSource) throws -> Data {
        var key = random.bytes(count: keySize)
        defer { wipe(&key) }
        return try keepassXMLv2(key: key)
    }

    // MARK: - helpers

    /// Exactly ASCII space, tab, LF and CR (not VT, FF, NBSP or any other Unicode space).
    static func isWhitespace(_ b: UInt8) -> Bool { b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D }

    static func isHexDigit(_ b: UInt8) -> Bool { (0x30...0x39).contains(b) || (0x41...0x46).contains(b) || (0x61...0x66).contains(b) }

    static func hexValue(_ b: UInt8) -> UInt8 {
        switch b {
        case 0x30...0x39: return b - 0x30
        case 0x41...0x46: return b - 0x41 + 10
        default: return b - 0x61 + 10
        }
    }

    /// Hex digits (either case, even count, already checked) to bytes.
    static func hexDecode(_ digits: [UInt8]) -> [UInt8] {
        stride(from: 0, to: digits.count - 1, by: 2).map { hexValue(digits[$0]) << 4 | hexValue(digits[$0 + 1]) }
    }

    /// Which element texts the key needs; text is the character data before an element's first child (ElementTree's
    /// `.text`). Elements in a namespace are not the plain names ElementTree's `find()` looks for.
    private final class Collector: NSObject, XMLParserDelegate {
        var path: [String?] = []
        var elements = 0
        var version: String?
        var data: String?
        var dataHash: String?
        var failure: KeyFileError?
        /// 1: collecting `Meta/Version`, 2: collecting `Key/Data`, 0: neither.
        var collecting = 0

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            elements += 1
            if elements > KeyFile.maxElements { return stop(parser, .malformed) }
            collecting = 0
            path.append((namespaceURI ?? "").isEmpty ? name : nil)
            guard path.count == 3 else { return }
            if path[1] == "Meta", path[2] == "Version", version == nil {
                version = ""; collecting = 1
            } else if path[1] == "Key", path[2] == "Data", data == nil {
                data = ""; collecting = 2
                dataHash = attributes["Hash"]
            }
        }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            if !path.isEmpty { path.removeLast() }
            collecting = 0
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) { append(string) }

        func parser(_ parser: XMLParser, foundCDATA block: Data) { append(String(decoding: block, as: UTF8.self)) }

        private func append(_ s: String) {
            if collecting == 1 { version = (version ?? "") + s } else if collecting == 2 { data = (data ?? "") + s }
        }

        func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) { stop(parser, .doctype) }
        func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
            stop(parser, .doctype)
        }
        func parser(_ parser: XMLParser, foundNotationDeclarationWithName name: String, publicID: String?, systemID: String?) {
            stop(parser, .doctype)
        }
        func parser(_ parser: XMLParser, foundUnparsedEntityDeclarationWithName name: String, publicID: String?,
                    systemID: String?, notationName: String?) { stop(parser, .doctype) }
        func parser(_ parser: XMLParser, foundElementDeclarationWithName elementName: String, model: String) { stop(parser, .doctype) }
        func parser(_ parser: XMLParser, resolveExternalEntityName name: String, systemID: String?) -> Data? {
            stop(parser, .doctype)
            return nil
        }

        func stop(_ parser: XMLParser, _ error: KeyFileError) {
            if failure == nil { failure = error }
            parser.abortParsing()
        }
    }

    private static func xmlKey(_ text: [UInt8]) throws -> [UInt8] {
        // KeePass never writes a DOCTYPE; refusing the bytes up front means no DTD (internal or external) and no
        // entity declaration ever reaches the parser (the importer's `KeePassTree.parse` does the same).
        let marker = Array("<!DOCTYPE".utf8)
        if text.count >= marker.count, (0...(text.count - marker.count)).contains(where: { text[$0..<$0 + marker.count].elementsEqual(marker) }) {
            throw KeyFileError.doctype
        }
        try checkDeclaredEncoding(text)
        let parser = XMLParser(data: Data(text))
        parser.shouldResolveExternalEntities = false
        parser.shouldProcessNamespaces = true
        let collector = Collector()
        parser.delegate = collector
        let ok = parser.parse()
        if let failure = collector.failure { throw failure }
        guard ok else { throw KeyFileError.malformed }

        let version = String(String.UnicodeScalarView(
            (collector.version ?? "").unicodeScalars.trimmingASCIIWhitespace()))
        // Every ASCII whitespace character is removed from the key text; anything else (an NBSP) stays and makes the
        // hex or Base64 invalid.
        var payload = [Unicode.Scalar]((collector.data ?? "").unicodeScalars.filter { !($0.isASCII && isWhitespace(UInt8($0.value))) })
        defer { for i in payload.indices { payload[i] = " " } }
        guard !payload.isEmpty else { throw KeyFileError("Key file XML has no key data") }
        if version.hasPrefix("2") {
            guard payload.count % 2 == 0, payload.allSatisfy({ $0.isASCII && isHexDigit(UInt8($0.value)) }) else {
                throw KeyFileError("Key file 2.0 data must be hexadecimal")
            }
            var digits = payload.map { UInt8($0.value) }
            defer { wipe(&digits) }
            var key = hexDecode(digits)
            if let expected = collector.dataHash, !expected.isEmpty {
                let actual = lowerHex(SHA256.hash(data: key))
                guard expected.unicodeScalars.count <= actual.count,
                      String(actual.prefix(expected.unicodeScalars.count)) == lowercasedASCII(expected) else {
                    wipe(&key)
                    throw KeyFileError("Key file hash does not match its data")
                }
            }
            return key
        }
        guard let key = base64(payload) else { throw KeyFileError("Key file 1.0 data must be Base64") }
        return key
    }

    /// An XML declaration may only declare UTF-8 or ASCII (KeePass and KeePassXC write UTF-8): any other declared
    /// encoding is refused as malformed, so the parser never reinterprets the bytes.
    private static func checkDeclaredEncoding(_ text: [UInt8]) throws {
        let open = Array("<?xml".utf8)
        guard text.count >= open.count, Array(text[0..<open.count]) == open else { return }
        var end = open.count
        while end + 1 < text.count, !(text[end] == 0x3F && text[end + 1] == 0x3E) { end += 1 }   // "?>"
        guard end + 1 < text.count else { throw KeyFileError.malformed }
        let declaration = String(decoding: text[open.count..<end], as: UTF8.self)
        guard let range = declaration.range(of: "encoding") else { return }
        let rest = declaration[range.upperBound...].drop(while: { $0 == "=" || $0.isWhitespace })
        guard let quote = rest.first, quote == "\"" || quote == "'" else { throw KeyFileError.malformed }
        let value = rest.dropFirst().prefix(while: { $0 != quote }).lowercased()
        guard ["utf-8", "utf8", "us-ascii", "ascii"].contains(value) else { throw KeyFileError.malformed }
    }

    /// Case-insensitive compare for the `Hash` attribute (hex digits only can match, so ASCII lower-casing suffices).
    private static func lowercasedASCII(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for c in s.unicodeScalars { out.append((0x41...0x5A).contains(c.value) ? Unicode.Scalar(c.value + 32)! : c) }
        return String(out)
    }

    /// Python `base64.b64decode(s, validate=True)` as Android ports it: the standard alphabet, correct padding;
    /// spare bits are ignored.
    static func base64(_ s: [Unicode.Scalar]) -> [UInt8]? {
        var len = s.count
        while len > 0, s[len - 1] == "=" { len -= 1 }
        let pads = s.count - len
        func value(_ c: Unicode.Scalar) -> UInt32? {
            switch c {
            case "A"..."Z": return c.value - 65
            case "a"..."z": return c.value - 97 + 26
            case "0"..."9": return c.value - 48 + 52
            case "+": return 62
            case "/": return 63
            default: return nil
            }
        }
        guard pads <= 2, s[0..<len].allSatisfy({ value($0) != nil }) else { return nil }
        let needed: Int
        switch len % 4 {
        case 0: needed = 0
        case 2: needed = 2
        case 3: needed = 1
        default: return nil
        }
        guard pads == needed, !(len == 0 && pads > 0) else { return nil }
        var out = [UInt8](); out.reserveCapacity(len * 6 / 8)
        var acc: UInt32 = 0, bits = 0
        for c in s[0..<len] {
            acc = ((acc << 6) | (value(c) ?? 0)) & 0xFFFFFF
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((acc >> UInt32(bits)) & 0xFF))
            }
        }
        return out
    }
}

private extension String.UnicodeScalarView {
    /// Drops leading and trailing ASCII space, tab, LF and CR only.
    func trimmingASCIIWhitespace() -> Substring.UnicodeScalarView {
        let ws: (Unicode.Scalar) -> Bool = { $0.isASCII && KeyFile.isWhitespace(UInt8($0.value)) }
        guard let first = firstIndex(where: { !ws($0) }), let last = lastIndex(where: { !ws($0) }) else {
            return Substring("").unicodeScalars
        }
        return self[first...last]
    }
}
