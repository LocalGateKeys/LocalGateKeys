/// Bad parameters or malformed shares (desktop `sss.SSSError`).
public struct SSSError: Error, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// Shamir's secret sharing over GF(2^8) for emergency-access shards: port of `src/localvault/sss.py` and Android
/// `Sss.kt` (vectors: `tests/vectors/sss`). The field uses the AES polynomial 0x11b; the secret is exactly 32 bytes;
/// share `x` (1...n) is `[x] + 32 bytes`; one `random.bytes(count: 32 * (k - 1))` call gives
/// `coeffs[j * (k - 1) + (d - 1)]`, the degree-`d` coefficient for secret byte `j`. `combine` cannot tell a wrong
/// share or too few shares: integrity comes from the signed `.lgkheir` envelope and the plan's entropy check.
///
/// Side channels (best effort): the log/exp tables are only indexed by public share indices (the Lagrange basis).
/// Secret bytes never index a table and never choose a branch: they only go through `mul`, a fixed eight-round
/// shift-and-xor multiply with masks. Working buffers are zeroed before return.
public enum SSS {
    public static let secretLength = 32
    public static let shareLength = 1 + secretLength
    public static let minK = 2
    public static let maxN = 5

    /// 0x03 generates the multiplicative group of GF(2^8) mod 0x11b (public table build, not secret data).
    static let tables: (exp: [Int], log: [Int]) = {
        var exp = [Int](repeating: 0, count: 510)
        var log = [Int](repeating: 0, count: 256)
        var value = 1
        for power in 0..<255 {
            exp[power] = value
            log[value] = power
            let reduce = (value & 0x80) != 0 ? 0x1B : 0
            value = value ^ (((value << 1) ^ reduce) & 0xFF)
        }
        for power in 255..<510 { exp[power] = exp[power - 255] }
        return (exp, log)
    }()

    /// `a * b` in GF(2^8) mod 0x11b: no table lookups and no data-dependent branches.
    static func mul(_ a0: Int, _ b0: Int) -> Int {
        var a = a0 & 0xFF, b = b0 & 0xFF, p = 0
        for _ in 0..<8 {
            p ^= a & -(b & 1)
            a = ((a << 1) ^ (0x1B & -(a >> 7))) & 0xFF
            b >>= 1
        }
        return p
    }

    /// `a / b` with the log/exp tables: only for public values (share indices); nil when `b` is 0.
    static func div(_ a: Int, _ b: Int) -> Int? {
        if b == 0 { return nil }
        if a == 0 { return 0 }
        return tables.exp[tables.log[a] + 255 - tables.log[b]]
    }

    /// Horner evaluation of `coeffs[0] + coeffs[1] x + ...` at `x`.
    static func evaluate(_ coeffs: [Int], _ x: Int) -> Int {
        var y = 0
        for i in coeffs.indices.reversed() { y = mul(y, x) ^ coeffs[i] }
        return y
    }

    /// Splits a 32-byte `secret` into `n` shares, any `k` of which recover it (2 <= k <= n <= 5).
    public static func split(_ secret: [UInt8], k: Int, n: Int, random: any RandomSource) throws -> [[UInt8]] {
        guard minK <= k, k <= n, n <= maxN else { throw SSSError("need \(minK) <= k <= n <= \(maxN)") }
        guard secret.count == secretLength else { throw SSSError("secret must be \(secretLength) bytes") }
        let degree = k - 1
        var coeffs = random.bytes(count: secretLength * degree)
        var poly = [Int](repeating: 0, count: k)
        defer {
            for i in coeffs.indices { coeffs[i] = 0 }
            for i in poly.indices { poly[i] = 0 }
        }
        guard coeffs.count == secretLength * degree else { throw SSSError("rng returned the wrong number of bytes") }
        var outs = [[UInt8]](repeating: [UInt8](repeating: 0, count: shareLength), count: n)
        for i in 0..<n { outs[i][0] = UInt8(i + 1) }
        for j in 0..<secretLength {
            poly[0] = Int(secret[j])
            for d in 1...degree { poly[d] = Int(coeffs[j * degree + d - 1]) }
            for i in 0..<n { outs[i][1 + j] = UInt8(evaluate(poly, i + 1)) }
        }
        return outs
    }

    /// Recovers the secret from 2...5 shares with distinct indices. Fewer than `k` shares give unrelated bytes.
    public static func combine(_ shares: [[UInt8]]) throws -> [UInt8] {
        guard (minK...maxN).contains(shares.count) else { throw SSSError("need \(minK) to \(maxN) shares") }
        guard shares.allSatisfy({ $0.count == shareLength }) else { throw SSSError("each share must be \(shareLength) bytes") }
        let xs = shares.map { Int($0[0]) }
        guard !xs.contains(0) else { throw SSSError("share index 0 is not allowed") }
        guard Set(xs).count == xs.count else { throw SSSError("duplicate share index") }
        // The Lagrange basis at x = 0 depends only on the public indices: L_i = prod(x_m) / prod(x_i - x_m), m != i.
        var basis: [Int] = []
        for (i, xi) in xs.enumerated() {
            var num = 1, den = 1
            for (m, xm) in xs.enumerated() where m != i {
                num = mul(num, xm)
                den = mul(den, xi ^ xm)
            }
            guard let l = div(num, den) else { throw SSSError("duplicate share index") }
            basis.append(l)
        }
        var out = [UInt8](repeating: 0, count: secretLength)
        for j in 0..<secretLength {
            var acc = 0
            for i in shares.indices { acc ^= mul(Int(shares[i][1 + j]), basis[i]) }
            out[j] = UInt8(acc)
        }
        return out
    }
}
