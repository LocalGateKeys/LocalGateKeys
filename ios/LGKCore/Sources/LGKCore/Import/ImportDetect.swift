import Foundation

/// Port of the Windows `detect.py`: content sniffing with the file extension as a hint.
/// Returns nil wherever Windows refuses the file (PGP, KeePass 1, unknown JSON/XML/zip, binary or empty files).
public enum ImportDetect {
    private static let kdbxMagic: [UInt8] = [0x03, 0xD9, 0xA2, 0x9A]
    private static let dashlaneZipFiles: Set<String> = ["credentials.csv", "securenotes.csv", "payments.csv", "ids.csv",
                                                       "personalinfo.csv"]

    public static func detect(data: Data, filename: String) -> ImportFormat? {
        guard data.count <= ImportSource.maxArchiveBytes else { return nil }
        let bytes = [UInt8](data)
        let suffix = Py.casefold(pathSuffix(filename))
        let head = Array(bytes.prefix(16))
        if head.starts(with: kdbxMagic) {
            if head.count >= 8, Array(head[4..<8]) == [0x65, 0xFB, 0x4B, 0xB5] { return nil }
            return .keePassKDBX
        }
        if suffix == ".kdbx" || suffix == ".kdb" { return nil }
        if head.starts(with: [0x50, 0x4B]) {
            guard let names = zipNames(bytes) else { return nil }
            if names.contains("export.data") { return .onePassword1PUX }
            let base = Set(names.map { Py.casefold(String($0.split(separator: "/", omittingEmptySubsequences: false).last ?? "")) })
            if base.contains("data.pgp") { return nil }
            if base.contains("data.json") { return .protonPass }
            if !base.isDisjoint(with: dashlaneZipFiles) { return .dashlane }
            return nil
        }
        if suffix == ".1pux" || suffix == ".1pif" { return nil }
        let asciiSpace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C]
        if Array(bytes.drop(while: { asciiSpace.contains($0) }).prefix(27)) == Array("-----BEGIN PGP MESSAGE-----".utf8)
            || suffix == ".pgp" || suffix == ".gpg" { return nil }
        let limit = 4 * 1024 * 1024
        guard let text = try? ImportText.decode(data.count > limit ? data.prefix(limit) : data) else { return nil }
        let stripped = Py.lstrip(text, ["\u{FEFF}", " ", "\t", "\r", "\n"])
        if stripped.hasPrefix("{") {
            guard let full = try? ImportText.decode(data) else { return nil }
            return detectJSON(full)
        }
        if stripped.hasPrefix("<") {
            return Py.prefix(stripped, 4096).contains("<KeePassFile") ? .keePassXML : nil
        }
        if stripped.isEmpty || Py.prefix(stripped, 4096).unicodeScalars.contains("\u{0}") { return nil }
        let first = Py.splitlines(stripped).first ?? ""
        if ["", ".csv", ".txt", ".tsv"].contains(suffix) || first.contains(",") || first.contains(";") || first.contains("\t") {
            guard let full = try? ImportText.decode(data) else { return nil }
            return detectCSV(full)
        }
        return nil
    }

    /// `PurePath.suffix`.
    static func pathSuffix(_ filename: String) -> String {
        let name = String(filename.split(separator: "/", omittingEmptySubsequences: false).last ?? "")
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex, name.index(after: dot) != name.endIndex else { return "" }
        return String(name[dot...])
    }

    static func detectJSON(_ text: String) -> ImportFormat? {
        guard let doc = try? PyJSON.parse(text), doc.isObject else { return nil }
        if doc["vaults"]?.isObject == true { return doc["encrypted"]?.isTrue == true ? nil : .protonPass }
        if doc["encrypted"]?.isTrue == true {
            if !(doc["passwordProtected"]?.truthy ?? false) { return nil }
            if doc.has("data") { return .bitwardenEncrypted }
        }
        if doc["items"]?.isList == true { return .bitwarden }
        if doc["accounts"]?.isList == true { return .onePassword1PUX }
        return nil
    }

    static func detectCSV(_ text: String) -> ImportFormat? {
        guard let header = try? CSVTable.header(text) else { return nil }
        let keys = Set(header.map(CSVTable.normalizeHeader))
        func has(_ s: Set<String>) -> Bool { s.isSubset(of: keys) }
        if has(["type", "name", "url", "username", "password", "note", "totp", "vault"]) { return .protonPass }
        if has(["login uri", "login username", "login password"]) { return .bitwarden }
        if has(["url", "username", "password", "extra", "grouping"]) { return .lastPass }
        if has(["title", "password"]), !keys.isDisjoint(with: ["username2", "otpsecret"])
            || (has(["title", "url", "username", "password", "note"]) && keys.contains("category")) { return .dashlane }
        if keys == ["title", "note"] || keys == ["title", "note", "category"] { return .dashlane }
        if ["payments", "personal", "ids"].contains(DashlaneImport.classify(header)) { return .dashlane }
        if has(["title", "url", "username", "password"]), !keys.isDisjoint(with: ["favorite", "archived", "tags"]) {
            return .onePasswordCSV
        }
        if has(["url", "username", "password", "httprealm", "formactionorigin"]) { return .firefox }
        if has(["title", "url", "username", "password", "otpauth"]) { return .appleCSV }
        if has(["account", "login name", "password"]) || has(["group", "title", "username", "password", "url"]) { return .keePassCSV }
        if has(["name", "url", "username", "password"]) { return .chrome }
        if has(["title", "url", "username", "password", "note"]) { return .dashlane }
        return .generic
    }

    /// Member names from the zip central directory (nil when it cannot be read).
    static func zipNames(_ b: [UInt8]) -> [String]? {
        func u16(_ i: Int) -> Int { Int(b[i]) | Int(b[i + 1]) << 8 }
        func u32(_ i: Int) -> Int { u16(i) | u16(i + 2) << 16 }
        guard b.count >= 22 else { return nil }
        var eocd = -1
        var i = b.count - 22
        let floor = max(0, b.count - 22 - 65_535)
        while i >= floor {
            if b[i] == 0x50, b[i + 1] == 0x4B, b[i + 2] == 0x05, b[i + 3] == 0x06 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { return nil }
        let count = u16(eocd + 10), size = u32(eocd + 12), offset = u32(eocd + 16)
        // Data prepended to the archive shifts every offset (zipfile's "concat").
        let shift = eocd - size - offset
        guard shift >= 0 else { return nil }
        var p = offset + shift
        var names: [String] = []
        for _ in 0..<count {
            guard p + 46 <= b.count, b[p] == 0x50, b[p + 1] == 0x4B, b[p + 2] == 0x01, b[p + 3] == 0x02 else { return nil }
            let flags = u16(p + 8), n = u16(p + 28), extra = u16(p + 30), comment = u16(p + 32)
            guard p + 46 + n <= b.count else { return nil }
            let raw = Array(b[(p + 46)..<(p + 46 + n)])
            let name = flags & 0x800 != 0 ? String(decoding: raw, as: UTF8.self)
                : String(String.UnicodeScalarView(raw.map { cp437($0) }))
            names.append(name)
            p += 46 + n + extra + comment
        }
        return names
    }

    private static let cp437High: [UInt32] = [
        0xC7, 0xFC, 0xE9, 0xE2, 0xE4, 0xE0, 0xE5, 0xE7, 0xEA, 0xEB, 0xE8, 0xEF, 0xEE, 0xEC, 0xC4, 0xC5,
        0xC9, 0xE6, 0xC6, 0xF4, 0xF6, 0xF2, 0xFB, 0xF9, 0xFF, 0xD6, 0xDC, 0xA2, 0xA3, 0xA5, 0x20A7, 0x192,
        0xE1, 0xED, 0xF3, 0xFA, 0xF1, 0xD1, 0xAA, 0xBA, 0xBF, 0x2310, 0xAC, 0xBD, 0xBC, 0xA1, 0xAB, 0xBB,
        0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
        0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
        0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
        0x3B1, 0xDF, 0x393, 0x3C0, 0x3A3, 0x3C3, 0xB5, 0x3C4, 0x3A6, 0x398, 0x3A9, 0x3B4, 0x221E, 0x3C6, 0x3B5, 0x2229,
        0x2261, 0xB1, 0x2265, 0x2264, 0x2320, 0x2321, 0xF7, 0x2248, 0xB0, 0x2219, 0xB7, 0x221A, 0x207F, 0xB2, 0x25A0, 0xA0,
    ]

    static func cp437(_ b: UInt8) -> Unicode.Scalar {
        b < 0x80 ? Unicode.Scalar(b) : Unicode.Scalar(cp437High[Int(b) - 0x80])!
    }
}
