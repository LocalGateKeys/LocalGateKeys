import XCTest
@testable import LGKCore

/// Shamir over GF(256) against the shared vectors in tests/vectors/sss (port of tests/test_sss.py and Android
/// `SssTest.kt`: the same vectors and checks).
final class SSSTests: XCTestCase {
    private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    private func int(_ v: JSONValue?) -> Int { if case .int(let i)? = v { return Int(i) }; return -1 }

    private func load(_ name: String) throws -> [String: JSONValue] {
        obj(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shared("sss/\(name)")))))
    }

    /// The slow, obviously right multiply: bit by bit with branches (test only).
    private func reference(_ a0: Int, _ b0: Int) -> Int {
        var a = a0, b = b0, p = 0
        for _ in 0..<8 {
            if b & 1 != 0 { p ^= a }
            let hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi != 0 { a ^= 0x1B }
            b >>= 1
        }
        return p
    }

    private struct CountingRandom: RandomSource {
        let value: [UInt8]
        let asked: Box
        final class Box: @unchecked Sendable { var count = -1 }
        func bytes(count: Int) -> [UInt8] { asked.count = count; return value }
    }

    func testHashicorpFieldVectors() throws {
        let h = try load("hashicorp.json")
        for c in arr(h["add"]) { XCTAssertEqual(int(obj(c)["out"]), int(obj(c)["a"]) ^ int(obj(c)["b"])) }
        let mult = arr(h["mult"])
        XCTAssertEqual(mult.count, 4)
        for c in mult { XCTAssertEqual(int(obj(c)["out"]), SSS.mul(int(obj(c)["a"]), int(obj(c)["b"]))) }
        for c in arr(h["div"]) { XCTAssertEqual(int(obj(c)["out"]), SSS.div(int(obj(c)["a"]), int(obj(c)["b"]))) }
        for c in arr(h["polynomial_eval"]) {
            let o = obj(c)
            let coeffs = (0...int(o["degree"])).map { $0 == 0 ? int(o["intercept"]) : 0x5A }
            XCTAssertEqual(int(o["out"]), SSS.evaluate(coeffs, int(o["x"])))
        }
        XCTAssertEqual(SSS.mul(0x57, 0x83), 0xC1)   // FIPS-197 4.2
    }

    func testMaskedMultiplyMatchesTheReferenceForEveryPair() {
        for a in 0...255 { for b in 0...255 where reference(a, b) != SSS.mul(a, b) { XCTFail("\(a)*\(b)") } }
    }

    func testDivideInvertsMultiply() {
        for a in 0...255 { for b in 1...255 where SSS.div(SSS.mul(a, b), b) != a { XCTFail("\(a)/\(b)") } }
        XCTAssertNil(SSS.div(3, 0))
    }

    func testV1VectorsSplitByteForByteAndCombineEveryListedSubset() throws {
        let cases = arr(try load("v1.json")["cases"])
        XCTAssertEqual(cases.count, 6)
        for c in cases {
            let f = obj(c)
            let name = str(f["name"])
            let coefficients = Vectors.hex(str(f["coefficients"]))
            let rng = CountingRandom(value: coefficients, asked: CountingRandom.Box())
            let secret = Vectors.hex(str(f["secret"]))
            let shares = try SSS.split(secret, k: int(f["k"]), n: int(f["n"]), random: rng)
            XCTAssertEqual(rng.asked.count, coefficients.count, name)
            let expected = arr(f["shares"]).map { Vectors.hex(str($0)) }
            XCTAssertEqual(shares, expected, name)
            for subset in arr(f["combine_subsets"]) {
                let picked = arr(subset).map { expected[int($0) - 1] }
                XCTAssertEqual(try SSS.combine(picked), secret, name)
                XCTAssertEqual(try SSS.combine(picked.reversed()), secret, name)
            }
        }
    }

    private func subsets(_ n: Int, _ k: Int) -> [[Int]] {
        if k == 0 { return [[]] }
        if n < k { return [] }
        return subsets(n - 1, k) + subsets(n - 1, k - 1).map { $0 + [n - 1] }
    }

    func testEveryKSubsetCombinesAndFreshSharesDiffer() throws {
        let random = SystemRandomSource()
        let secret = random.bytes(count: 32)
        for n in 2...5 {
            for k in 2...n {
                let shares = try SSS.split(secret, k: k, n: n, random: random)
                for s in subsets(n, k) { XCTAssertEqual(try SSS.combine(s.map { shares[$0] }), secret) }
            }
        }
        let a = try SSS.split(secret, k: 2, n: 3, random: random)
        let b = try SSS.split(secret, k: 2, n: 3, random: random)
        XCTAssertNotEqual(a[0], b[0])
    }

    func testOneShareBelowKIsUniformExactly() {
        // k = 2: for every x and secret byte, the 256 coefficients map onto all 256 share values.
        for x in 1...5 {
            for s in 0...255 {
                let seen = Set((0...255).map { SSS.evaluate([s, $0], x) })
                if seen.count != 256 { XCTFail("x=\(x) s=\(s)") }
            }
        }
    }

    func testKMinusOneSharesReconstructUnrelatedBytes() throws {
        let random = SystemRandomSource()
        let secret = [UInt8](repeating: 0, count: 32)
        var matches = 0
        for _ in 0..<1000 {
            let shares = try SSS.split(secret, k: 3, n: 5, random: random)
            matches += try SSS.combine(Array(shares.prefix(2))).filter { $0 == 0 }.count
        }
        // 1000 * 32 bytes, 1/256 expected to match: about 125 (sd about 11); six sd either side.
        XCTAssertTrue((60...190).contains(matches), "matches \(matches)")
    }

    func testRefusals() throws {
        let r = FixedRandom(value: [UInt8](repeating: 7, count: 256))
        let secret = [UInt8](repeating: 1, count: 32)
        for (k, n) in [(1, 2), (3, 2), (2, 6), (0, 0), (6, 6)] {
            XCTAssertThrowsError(try SSS.split(secret, k: k, n: n, random: r))
        }
        XCTAssertThrowsError(try SSS.split([UInt8](repeating: 0, count: 31), k: 2, n: 2, random: r))
        XCTAssertThrowsError(try SSS.split([UInt8](repeating: 0, count: 33), k: 2, n: 2, random: r))
        XCTAssertThrowsError(try SSS.split(secret, k: 3, n: 3, random: FixedRandom(value: [UInt8](repeating: 0, count: 10))))
        let shares = try SSS.split(secret, k: 2, n: 3, random: SystemRandomSource())
        XCTAssertThrowsError(try SSS.combine([]))
        XCTAssertThrowsError(try SSS.combine([shares[0]]))
        XCTAssertThrowsError(try SSS.combine([[UInt8]](repeating: shares[0], count: 6)))
        XCTAssertThrowsError(try SSS.combine([shares[0], shares[0]]))
        var sameIndex = shares[1]; sameIndex[0] = 1; sameIndex[1] = 9
        XCTAssertThrowsError(try SSS.combine([shares[0], sameIndex]))
        XCTAssertThrowsError(try SSS.combine([shares[0], Array(shares[1].prefix(32))]))
        var zero = shares[1]; zero[0] = 0
        XCTAssertThrowsError(try SSS.combine([shares[0], zero]))
    }
}
