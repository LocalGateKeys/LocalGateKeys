/// Strict base64 matching the desktop's `b64decode(validate=True)` plus the canonical re-encode check.
public enum Base64Error: Error, Equatable { case malformed }

private let stdAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
private let urlAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

private func encode(_ bytes: [UInt8], alphabet: [UInt8], pad: Bool) -> String {
    var out = [UInt8](); out.reserveCapacity((bytes.count + 2) / 3 * 4)
    var i = 0
    while i < bytes.count {
        let b0 = UInt32(bytes[i])
        let b1 = i + 1 < bytes.count ? UInt32(bytes[i + 1]) : 0
        let b2 = i + 2 < bytes.count ? UInt32(bytes[i + 2]) : 0
        let n = (b0 << 16) | (b1 << 8) | b2
        out.append(alphabet[Int((n >> 18) & 63)])
        out.append(alphabet[Int((n >> 12) & 63)])
        if i + 1 < bytes.count { out.append(alphabet[Int((n >> 6) & 63)]) } else if pad { out.append(61) }
        if i + 2 < bytes.count { out.append(alphabet[Int(n & 63)]) } else if pad { out.append(61) }
        i += 3
    }
    return String(decoding: out, as: UTF8.self)
}

/// `body` is unpadded-or-padded text already validated for padding placement; decodes and rejects non-zero spare bits.
private func decodeCore(_ chars: [UInt8], alphabet: [UInt8]) throws -> [UInt8] {
    var table = [Int](repeating: -1, count: 256)
    for (i, c) in alphabet.enumerated() { table[Int(c)] = i }
    if chars.count % 4 == 1 { throw Base64Error.malformed }
    var out = [UInt8](); out.reserveCapacity(chars.count / 4 * 3)
    var acc: UInt32 = 0, bits = 0
    for c in chars {
        let v = table[Int(c)]
        if v < 0 { throw Base64Error.malformed }
        acc = (acc << 6) | UInt32(v); bits += 6
        if bits >= 8 { bits -= 8; out.append(UInt8((acc >> UInt32(bits)) & 0xFF)) }
    }
    // Spare bits must be zero (canonical form).
    if bits > 0 && (acc & ((1 << UInt32(bits)) - 1)) != 0 { throw Base64Error.malformed }
    return out
}

public enum Base64 {
    public static func encode(_ bytes: [UInt8]) -> String { LGKCore.encode(bytes, alphabet: stdAlphabet, pad: true) }

    /// Standard alphabet, mandatory padding, no whitespace, zero spare bits.
    public static func decodeStrict(_ text: String) throws -> [UInt8] {
        var chars = Array(text.utf8)
        if chars.count % 4 != 0 { throw Base64Error.malformed }
        var pad = 0
        while pad < 2, chars.last == 61 { chars.removeLast(); pad += 1 }
        if chars.contains(61) { throw Base64Error.malformed }
        let out = try decodeCore(chars, alphabet: stdAlphabet)
        if encode(out) != text { throw Base64Error.malformed }
        return out
    }
}

public enum Base64URL {
    public static func encodeNoPad(_ bytes: [UInt8]) -> String { LGKCore.encode(bytes, alphabet: urlAlphabet, pad: false) }

    /// URL-safe alphabet, no padding allowed, zero spare bits.
    public static func decodeNoPadStrict(_ text: String) throws -> [UInt8] {
        let out = try decodeCore(Array(text.utf8), alphabet: urlAlphabet)
        if encodeNoPad(out) != text { throw Base64Error.malformed }
        return out
    }
}

/// Unpadded base64url, as desktop `passkeys.b64u_encode`.
public func base64URLNoPad(_ bytes: [UInt8]) -> String { Base64URL.encodeNoPad(bytes) }

/// Desktop `passkeys.b64u_decode`: URL-safe alphabet only, no padding, at most `maxBytes` decoded bytes.
/// Lenient about spare bits like Python's `urlsafe_b64decode`. Returns nil where the desktop raises.
public func decodeBase64URL(_ s: String, maxBytes: Int) -> [UInt8]? {
    let chars = Array(s.utf8)
    if chars.count > (maxBytes * 4 + 2) / 3 || chars.count % 4 == 1 { return nil }
    var table = [Int](repeating: -1, count: 256)
    for (i, c) in urlAlphabet.enumerated() { table[Int(c)] = i }
    var out = [UInt8](); out.reserveCapacity(chars.count * 3 / 4)
    var acc: UInt32 = 0, bits = 0
    for c in chars {
        let v = table[Int(c)]
        if v < 0 { return nil }
        acc = ((acc << 6) | UInt32(v)) & 0xFFFFFF; bits += 6
        if bits >= 8 { bits -= 8; out.append(UInt8((acc >> UInt32(bits)) & 0xFF)) }
    }
    return out.count > maxBytes ? nil : out
}
