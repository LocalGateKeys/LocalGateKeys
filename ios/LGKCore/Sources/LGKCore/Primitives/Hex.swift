/// Lowercase hex of `bytes`; the one hex encoder of the package.
func lowerHex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
    let digits = Array("0123456789abcdef".unicodeScalars)
    var s = String.UnicodeScalarView()
    for b in bytes { s.append(digits[Int(b >> 4)]); s.append(digits[Int(b & 15)]) }
    return String(s)
}

/// Orders strings by Unicode scalar values (Python `str` order), not by canonical equivalence.
func scalarOrder(_ a: String, _ b: String) -> Bool {
    a.unicodeScalars.lexicographicallyPrecedes(b.unicodeScalars) { $0.value < $1.value }
}
