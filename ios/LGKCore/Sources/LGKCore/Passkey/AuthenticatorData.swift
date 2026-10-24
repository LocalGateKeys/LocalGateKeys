import Crypto

public enum Passkey {
    /// b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41
    public static let aaguid: [UInt8] = [0xb7, 0xd2, 0xa6, 0xf0, 0x1c, 0x4e, 0x4a, 0x5b,
                                         0x9e, 0x3d, 0x5a, 0x1f, 0x7c, 0x2e, 0x8d, 0x41]
    public static let credentialIDLength = 16

    static let flagUP: UInt8 = 0x01, flagUV: UInt8 = 0x04, flagBE: UInt8 = 0x08, flagBS: UInt8 = 0x10, flagAT: UInt8 = 0x40
}

/// SHA-256(rpId) ‖ flags ‖ 00000000 [‖ AAGUID ‖ len(credId) u16 BE ‖ credId ‖ COSE key].
/// Flags UP|BE|BS, +UV when `userVerified`, +AT when `attested` is given.
public func authenticatorData(rpID: String, userVerified: Bool,
                              attested: (credentialID: [UInt8], coseKey: [UInt8])?) -> [UInt8] {
    var flags = Passkey.flagUP | Passkey.flagBE | Passkey.flagBS
    if userVerified { flags |= Passkey.flagUV }
    if attested != nil { flags |= Passkey.flagAT }
    var out = Array(SHA256.hash(data: Array(rpID.utf8)))
    out.append(flags)
    out += [0, 0, 0, 0]
    if let a = attested {
        precondition(a.credentialID.count <= 0xFFFF, "credential id length must fit in u16")
        out += Passkey.aaguid
        out += [UInt8((a.credentialID.count >> 8) & 0xFF), UInt8(a.credentialID.count & 0xFF)]
        out += a.credentialID
        out += a.coseKey
    }
    return out
}

/// COSE_Key `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in that order.
public func coseES256Key(_ key: P256.Signing.PublicKey) -> [UInt8] {
    let raw = Array(key.rawRepresentation)
    return CBOR.map([
        (.int(1), .int(2)), (.int(3), .int(-7)), (.int(-1), .int(1)),
        (.int(-2), .bytes(Array(raw[0..<32]))), (.int(-3), .bytes(Array(raw[32..<64]))),
    ]).encoded
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}` in desktop key order.
public func noneAttestationObject(authData: [UInt8]) -> [UInt8] {
    CBOR.map([(.text("fmt"), .text("none")), (.text("attStmt"), .map([])), (.text("authData"), .bytes(authData))]).encoded
}
