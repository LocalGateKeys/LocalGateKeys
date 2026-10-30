import Foundation

/// A classic (non-zip64) zip writer for stored members, laid out byte for byte as Python's `zipfile` writes
/// `backup._full_zip_info` members: version 2.0, no data descriptor, date 1980-01-01 00:00, MS-DOS host, external
/// attributes `0o600 << 16`, no extra fields and no comments. Non-ASCII names set the UTF-8 flag, as Python does.
public struct ZipWriter: Sendable {
    /// Zip32 field limit as an `Int`: 0xFFFF_FFFF, or `Int.max` on 32-bit watchOS devices where that does not fit.
    static let limit32 = Int(clamping: Int64(0xFFFF_FFFF))

    public enum Failure: Error, Equatable, Sendable { case tooLarge, tooManyEntries, unsafeName }

    // Data, so the finished archive is handed over without another copy.
    private var out = Data()
    private var central = Data()
    private var count = 0

    public init() {}

    /// Bytes written so far (the local headers and data; the central directory comes at `finish`).
    public var size: Int { out.count }

    public mutating func addStored(name: String, data: [UInt8]) throws { try addStored(name: name, data: Data(data)) }

    public mutating func addStored(name: String, data: Data) throws {
        guard ZipReader.isSafe(name) else { throw Failure.unsafeName }
        let nameBytes = Array(name.utf8)
        guard nameBytes.count <= 0xFFFF else { throw Failure.unsafeName }
        guard count < 0xFFFF else { throw Failure.tooManyEntries }
        guard data.count < Self.limit32, out.count < Self.limit32,
              out.count + 30 + nameBytes.count + data.count < Self.limit32 else { throw Failure.tooLarge }
        let flags: UInt16 = name.unicodeScalars.allSatisfy(\.isASCII) ? 0 : 0x800
        let crc = ZipReader.crc32(data)
        let offset = UInt32(out.count)
        // Local file header.
        Self.u32(0x0403_4B50, &out); Self.u16(20, &out); Self.u16(flags, &out); Self.u16(0, &out)
        Self.u16(0, &out); Self.u16(0x0021, &out)
        Self.u32(crc, &out); Self.u32(UInt32(data.count), &out); Self.u32(UInt32(data.count), &out)
        Self.u16(UInt16(nameBytes.count), &out); Self.u16(0, &out)
        out.append(contentsOf: nameBytes)
        out.append(data)
        // Central directory record.
        Self.u32(0x0201_4B50, &central); Self.u16(20, &central); Self.u16(20, &central); Self.u16(flags, &central)
        Self.u16(0, &central); Self.u16(0, &central); Self.u16(0x0021, &central)
        Self.u32(crc, &central); Self.u32(UInt32(data.count), &central); Self.u32(UInt32(data.count), &central)
        Self.u16(UInt16(nameBytes.count), &central); Self.u16(0, &central); Self.u16(0, &central)
        Self.u16(0, &central); Self.u16(0, &central); Self.u32(0o600 << 16, &central); Self.u32(offset, &central)
        central.append(contentsOf: nameBytes)
        count += 1
    }

    /// The finished archive: members, central directory and the end-of-central-directory record. The writer is
    /// left empty (the bytes are moved out, not copied).
    public mutating func finish() throws -> Data {
        guard out.count + central.count + 22 < Self.limit32 else { throw Failure.tooLarge }
        var result = out
        let directoryOffset = UInt32(result.count)
        out = Data()
        result += central
        Self.u32(0x0605_4B50, &result); Self.u16(0, &result); Self.u16(0, &result)
        Self.u16(UInt16(count), &result); Self.u16(UInt16(count), &result)
        Self.u32(UInt32(central.count), &result); Self.u32(directoryOffset, &result); Self.u16(0, &result)
        central = Data()
        count = 0
        return result
    }

    private static func u16(_ v: UInt16, _ o: inout Data) { o.append(UInt8(v & 0xFF)); o.append(UInt8(v >> 8)) }
    private static func u32(_ v: UInt32, _ o: inout Data) {
        u16(UInt16(v & 0xFFFF), &o); u16(UInt16(v >> 16), &o)
    }
}
