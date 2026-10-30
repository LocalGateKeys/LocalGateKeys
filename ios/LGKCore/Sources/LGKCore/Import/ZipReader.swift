import Foundation
#if canImport(Compression)
import Compression
#endif

/// One member of a zip archive, from the central directory.
public struct ZipEntry: Sendable, Equatable {
    public let name: String
    public let method: UInt16
    public let flags: UInt16
    public let crc: UInt32
    public let compressedSize: Int
    public let uncompressedSize: Int
    let localHeaderOffset: Int
    /// The name bytes as stored in the central directory (the local header must repeat them, as Python checks).
    var rawName: [UInt8] = []

    public var isEncrypted: Bool { flags & 0x1 != 0 }
    public var isDirectory: Bool { name.hasSuffix("/") }
}

/// A bounded reader for untrusted import archives (1PUX, Proton Pass and Dashlane zips): classic zip only (zip64 is
/// refused), stored or raw-deflated members, no encrypted members, no `..`/absolute/drive names, no duplicate names, a
/// cap on entries, archive size, decompressed size and compression ratio. Every member is CRC-checked, and its local
/// header must carry the central directory's name. Full backups (`FullBackupV2`) read through it too, stored members only.
public struct ZipReader: Sendable {
    public enum Failure: Error, Equatable, Sendable {
        case corrupt, zip64, unsafeName, duplicateName, tooManyEntries, tooLarge, ratio, encrypted, unsupportedMethod

        public var message: String {
            switch self {
            case .corrupt: return String(localized: "The zip archive is damaged or incomplete", bundle: .module)
            case .zip64: return String(localized: "This zip archive uses the zip64 format, which is not supported", bundle: .module)
            case .unsafeName: return String(localized: "The zip archive contains a file name that points outside the archive and was refused", bundle: .module)
            case .duplicateName: return String(localized: "The zip archive contains the same file name twice and was refused", bundle: .module)
            case .tooManyEntries: return String(localized: "The zip archive contains too many files", bundle: .module)
            case .tooLarge: return String(localized: "A file inside the zip archive is too large", bundle: .module)
            case .ratio: return String(localized: "A file inside the zip archive is compressed suspiciously well and was refused", bundle: .module)
            case .encrypted: return String(localized: "A file inside the zip archive is encrypted", bundle: .module)
            case .unsupportedMethod: return String(localized: "A file inside the zip archive uses an unsupported compression method", bundle: .module)
            }
        }
    }

    /// A member may not expand more than this many times over its compressed size (above `ratioFloor` bytes).
    public static let maxRatio = 200
    static let ratioFloor = 1024 * 1024
    public static let defaultMaxEntries = 20_005

    private let bytes: ByteView
    private let list: [ZipEntry]
    private let shift: Int

    public init(data: Data, maxBytes: Int, maxEntries: Int) throws {
        guard data.count <= maxBytes else { throw Failure.tooLarge }
        // No copy of the archive: a zero-based view over `data` (which may be memory-mapped).
        let b = ByteView(data)
        bytes = b
        func u16(_ i: Int) -> Int { Int(b[i]) | Int(b[i + 1]) << 8 }
        func u32(_ i: Int) -> Int { u16(i) | u16(i + 2) << 16 }
        /// A saturated (0xFFFF_FFFF) field, the zip64 marker; tested by halves so it compiles for 32-bit watchOS.
        func saturated32(_ i: Int) -> Bool { u16(i) == 0xFFFF && u16(i + 2) == 0xFFFF }
        guard b.count >= 22 else { throw Failure.corrupt }
        var eocd = -1
        var i = b.count - 22
        let floor = max(0, b.count - 22 - 65_535)
        while i >= floor {
            if b[i] == 0x50, b[i + 1] == 0x4B, b[i + 2] == 0x05, b[i + 3] == 0x06 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw Failure.corrupt }
        // A zip64 locator (and its 56-byte record) may sit between the central directory and the classic record;
        // it is harmless while every classic field is valid (saturated fields are refused below).
        var cdEnd = eocd
        if eocd >= 20, u32(eocd - 20) == 0x0706_4B50 {
            cdEnd = eocd - 20
            if cdEnd >= 56, u32(cdEnd - 56) == 0x0606_4B50 { cdEnd -= 56 }
        }
        let disk = u16(eocd + 4), cdDisk = u16(eocd + 6), countHere = u16(eocd + 8)
        let count = u16(eocd + 10), size = u32(eocd + 12), offset = u32(eocd + 16)
        if count == 0xFFFF || saturated32(eocd + 12) || saturated32(eocd + 16) { throw Failure.zip64 }
        guard disk == 0, cdDisk == 0, countHere == count else { throw Failure.corrupt }
        guard count <= maxEntries else { throw Failure.tooManyEntries }
        // Data prepended to the archive shifts every offset (as Python's zipfile allows).
        let shift = cdEnd - size - offset
        guard shift >= 0 else { throw Failure.corrupt }
        self.shift = shift
        var p = offset + shift
        var entries: [ZipEntry] = []
        var seen = Set<String>()
        for _ in 0..<count {
            guard p + 46 <= cdEnd, u32(p) == 0x0201_4B50 else { throw Failure.corrupt }
            let flags = u16(p + 8), method = u16(p + 10), crc = u32(p + 16)
            let csize = u32(p + 20), usize = u32(p + 24)
            let n = u16(p + 28), extra = u16(p + 30), comment = u16(p + 32), local = u32(p + 42)
            if saturated32(p + 20) || saturated32(p + 24) || saturated32(p + 42) { throw Failure.zip64 }
            guard p + 46 + n + extra + comment <= cdEnd else { throw Failure.corrupt }
            let raw = Array(b[(p + 46)..<(p + 46 + n)])
            let name: String
            if flags & 0x800 != 0 {
                guard let s = String(bytes: raw, encoding: .utf8) else { throw Failure.corrupt }
                name = s
            } else {
                name = String(String.UnicodeScalarView(raw.map { ImportDetect.cp437($0) }))
            }
            guard Self.isSafe(name) else { throw Failure.unsafeName }
            guard seen.insert(name).inserted else { throw Failure.duplicateName }
            entries.append(ZipEntry(name: name, method: UInt16(method), flags: UInt16(flags), crc: UInt32(crc),
                                    compressedSize: csize, uncompressedSize: usize, localHeaderOffset: local + shift,
                                    rawName: raw))
            p += 46 + n + extra + comment
        }
        list = entries
    }

    /// Relative names only: no empty, `.` or `..` component, no leading slash or backslash, no drive letter, no NUL.
    static func isSafe(_ name: String) -> Bool {
        guard !name.isEmpty, !name.unicodeScalars.contains("\u{0}") else { return false }
        if name.hasPrefix("/") || name.hasPrefix("\\") { return false }
        let u = Array(name.unicodeScalars)
        if u.count >= 2, u[1] == ":" { return false }
        let parts = name.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "/" || $0 == "\\" })
        for (i, part) in parts.enumerated() {
            if part == ".." || part == "." { return false }
            if part.isEmpty, i != parts.count - 1 { return false }
        }
        return true
    }

    public func entries() -> [ZipEntry] { list }

    public func entry(named name: String) -> ZipEntry? { list.first { $0.name == name } }

    /// The member's bytes, refusing more than `limit` decompressed bytes, encrypted members, unknown methods, a
    /// compression ratio above `maxRatio` and any CRC or size mismatch.
    public func read(_ e: ZipEntry, limit: Int) throws -> Data {
        if e.isEncrypted { throw Failure.encrypted }
        guard e.method == 0 || e.method == 8 else { throw Failure.unsupportedMethod }
        guard e.uncompressedSize <= limit else { throw Failure.tooLarge }
        try Self.checkRatio(e.uncompressedSize, e.compressedSize)
        let p = e.localHeaderOffset
        let b = bytes
        guard p + 30 <= b.count, b[p] == 0x50, b[p + 1] == 0x4B, b[p + 2] == 0x03, b[p + 3] == 0x04 else {
            throw Failure.corrupt
        }
        let n = Int(b[p + 26]) | Int(b[p + 27]) << 8, extra = Int(b[p + 28]) | Int(b[p + 29]) << 8
        let start = p + 30 + n + extra
        // A local header naming another file than the central directory is refused (Python's zipfile does too).
        guard p + 30 + n <= b.count, e.rawName.isEmpty || Array(b[(p + 30)..<(p + 30 + n)]) == e.rawName else {
            throw Failure.corrupt
        }
        guard start <= b.count, e.compressedSize <= b.count - start else { throw Failure.corrupt }
        let payload = b.data(start..<(start + e.compressedSize))
        let out: Data
        if e.method == 0 {
            guard e.compressedSize == e.uncompressedSize else { throw Failure.corrupt }
            out = payload
        } else {
            // The bound is the smaller of the caller's limit and what the ratio allows for this member.
            let ratioCap = max(Self.ratioFloor, e.compressedSize.multipliedReportingOverflow(by: Self.maxRatio).partialValue)
            out = try Inflate.raw(payload, limit: limit, ratioLimit: ratioCap)
        }
        guard out.count == e.uncompressedSize, Self.crc32(out) == e.crc else { throw Failure.corrupt }
        return out
    }

    static func checkRatio(_ uncompressed: Int, _ compressed: Int) throws {
        if uncompressed > ratioFloor, uncompressed / max(compressed, 1) > maxRatio { throw Failure.ratio }
    }

    private static let crcTable: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func crc32(_ data: Data) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        data.withUnsafeBytes { raw in
            for byte in raw { c = crcTable[Int((c ^ UInt32(byte)) & 0xFF)] ^ (c >> 8) }
        }
        return c ^ 0xFFFF_FFFF
    }
}

/// Zero-based byte access to a `Data` (possibly a slice or memory-mapped) without copying it.
struct ByteView: Sendable {
    private let data: Data
    private let base: Int
    init(_ data: Data) { self.data = data; base = data.startIndex }
    var count: Int { data.count }
    subscript(i: Int) -> UInt8 { data[base + i] }
    subscript(r: Range<Int>) -> [UInt8] { [UInt8](data[(base + r.lowerBound)..<(base + r.upperBound)]) }
    /// A copy of just this range, zero-based.
    func data(_ r: Range<Int>) -> Data { data.subdata(in: (base + r.lowerBound)..<(base + r.upperBound)) }
}

/// Bounded raw-DEFLATE and gzip decoding.
enum Inflate {
    /// Raw DEFLATE (zip method 8). `tooLarge` past `limit` output bytes, `ratio` past `ratioLimit`, `corrupt` otherwise.
    static func raw(_ input: Data, limit: Int, ratioLimit: Int = .max) throws -> Data {
        #if canImport(Compression)
        let dstSize = 64 * 1024
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: dstSize)
        defer { dst.deallocate() }
        let streamPtr = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { streamPtr.deallocate() }
        guard compression_stream_init(streamPtr, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
            throw ZipReader.Failure.corrupt
        }
        defer { compression_stream_destroy(streamPtr) }
        var out = Data()
        return try input.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Data in
            streamPtr.pointee.src_ptr = src.bindMemory(to: UInt8.self).baseAddress ?? UnsafePointer(dst)
            streamPtr.pointee.src_size = src.count
            while true {
                streamPtr.pointee.dst_ptr = dst
                streamPtr.pointee.dst_size = dstSize
                let status = compression_stream_process(streamPtr, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                let produced = dstSize - streamPtr.pointee.dst_size
                if produced > 0 {
                    if out.count + produced > limit { throw ZipReader.Failure.tooLarge }
                    if out.count + produced > ratioLimit { throw ZipReader.Failure.ratio }
                    out.append(dst, count: produced)
                }
                switch status {
                case COMPRESSION_STATUS_END: return out
                case COMPRESSION_STATUS_OK:
                    // No progress with input exhausted: the stream is truncated.
                    if produced == 0, streamPtr.pointee.src_size == 0 { throw ZipReader.Failure.corrupt }
                default: throw ZipReader.Failure.corrupt
                }
            }
        }
        #else
        throw ZipReader.Failure.unsupportedMethod
        #endif
    }

    /// One gzip member (RFC 1952) with its CRC and length checked.
    static func gunzip(_ data: Data, limit: Int) throws -> Data {
        let b = [UInt8](data)
        guard b.count >= 18, b[0] == 0x1F, b[1] == 0x8B, b[2] == 8 else { throw ZipReader.Failure.corrupt }
        let flags = b[3]
        guard flags & 0xE0 == 0 else { throw ZipReader.Failure.corrupt }
        var p = 10
        if flags & 0x04 != 0 {
            guard p + 2 <= b.count else { throw ZipReader.Failure.corrupt }
            p += 2 + (Int(b[p]) | Int(b[p + 1]) << 8)
        }
        for bit in [UInt8(0x08), 0x10] where flags & bit != 0 {
            while p < b.count, b[p] != 0 { p += 1 }
            p += 1
        }
        if flags & 0x02 != 0 { p += 2 }
        guard p + 8 <= b.count else { throw ZipReader.Failure.corrupt }
        let out = try raw(Data(b[p..<(b.count - 8)]), limit: limit)
        func u32(_ i: Int) -> UInt32 { UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24 }
        guard u32(b.count - 8) == ZipReader.crc32(out), u32(b.count - 4) == UInt32(truncatingIfNeeded: out.count) else {
            throw ZipReader.Failure.corrupt
        }
        return out
    }
}
