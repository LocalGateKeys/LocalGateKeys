import XCTest
import Crypto
@testable import LGKCore

/// `.lgkshare` v1.1 sender options and signed revoke notices (desktop `share.py` seal / open_package,
/// `share_revoke.py`), with the cross-language notice in `tests/vectors/share/revoke_v1.json`.
final class ShareRevokeTests: XCTestCase {
    private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }

    private let item: [String: JSONValue] = ["kind": .string("note"), "title": .string("Door"), "notes": .string("1234")]
    private let code = "abandon ability able about above absent"
    private let packageID = "0b9c3c6e-6f0a-4c3e-9d6b-2f1a7e5c4d3b"

    private func notice(_ key: Curve25519.Signing.PrivateKey, id: String, signer: String = "dev-a",
                        issuedAt: Int64 = 1_800_000_000) throws -> [UInt8] {
        let body: [String: JSONValue] = ["format": .int(1), "package_id": .string(id), "signer": .string(signer),
                                         "issued_at": .int(issuedAt)]
        let message = ShareRevoke.label + (try CanonicalJSON.encode(.object(body), dialect: .utf8))
        var o = body
        o["sig"] = .string(Base64.encode(Array(try key.signature(for: message))))
        return try CanonicalJSON.encode(.object(o), dialect: .utf8)
    }

    func testVectorNoticeVerifies() throws {
        let v = obj(try CanonicalJSON.parse(Array(try Vectors.data("../share/revoke_v1.json"))))
        let raw = Array(str(v["notice"]).utf8)
        let key = try Base64.decodeStrict(str(v["public_key"]))
        XCTAssertEqual(try ShareRevoke.verify(raw, publicKey: key, packageID: str(v["package_id"])), str(v["package_id"]))
        let got = ShareRevoke.collect(files: [(name: str(v["package_id"]) + ".lgkrevoke", data: raw)],
                                      trusted: [str(v["signer"]): str(v["public_key"])])
        XCTAssertEqual(got, [str(v["package_id"])])
    }

    func testVerifyRejectsOtherPackageBadSignatureAndDamage() throws {
        let key = Curve25519.Signing.PrivateKey(), pub = Array(key.publicKey.rawRepresentation)
        let raw = try notice(key, id: packageID)
        XCTAssertEqual(try ShareRevoke.verify(raw, publicKey: pub, packageID: packageID), packageID)
        XCTAssertThrowsError(try ShareRevoke.verify(raw, publicKey: pub, packageID: "1b9c3c6e-6f0a-4c3e-9d6b-2f1a7e5c4d3b")) {
            XCTAssertEqual(($0 as? ShareRevoke.RevokeError)?.reason, "other-package")
        }
        let other = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        XCTAssertThrowsError(try ShareRevoke.verify(raw, publicKey: other, packageID: packageID)) {
            XCTAssertEqual(($0 as? ShareRevoke.RevokeError)?.reason, "bad-signature")
        }
        let upper = try notice(key, id: packageID.uppercased())
        XCTAssertThrowsError(try ShareRevoke.verify(upper, publicKey: pub, packageID: packageID)) {
            XCTAssertEqual(($0 as? ShareRevoke.RevokeError)?.reason, "bad-revoke")
        }
        XCTAssertThrowsError(try ShareRevoke.verify(raw + Array(repeating: 0x20, count: 1100), publicKey: pub, packageID: packageID))
    }

    func testCollectNeedsTrustedSignerAndSuffix() throws {
        let key = Curve25519.Signing.PrivateKey()
        let keyText = Base64.encode(Array(key.publicKey.rawRepresentation))
        let raw = try notice(key, id: packageID)
        XCTAssertEqual(ShareRevoke.collect(files: [(name: "\(packageID).lgkrevoke", data: raw)], trusted: ["dev-a": keyText]),
                       [packageID])
        XCTAssertEqual(ShareRevoke.collect(files: [(name: "\(packageID).lgkrevoke", data: raw)], trusted: ["dev-b": keyText]), [])
        XCTAssertEqual(ShareRevoke.collect(files: [(name: "\(packageID).tmp", data: raw)], trusted: ["dev-a": keyText]), [])
        XCTAssertEqual(ShareRevoke.collect(files: [(name: "x.lgkrevoke", data: Array("{}".utf8))], trusted: ["dev-a": keyText]), [])
    }

    func testSealOptionsAndRevokedOpen() throws {
        let now: Int64 = 1_800_000_000
        let plain = try Share.seal(item: item, code: code, sender: "iPhone", now: now, packageID: packageID,
                                   salt: Array(repeating: 1, count: 16), nonce: Array(repeating: 2, count: 12))
        let same = try Share.seal(item: item, code: code, sender: "iPhone", now: now, expires: nil, oneUse: false,
                                  packageID: packageID, salt: Array(repeating: 1, count: 16), nonce: Array(repeating: 2, count: 12))
        XCTAssertEqual(plain, same)

        let short = try Share.seal(item: item, code: code, sender: "iPhone", now: now, expires: now + 3600, oneUse: true)
        let opened = try Share.open(short, code: code, now: now + 10)
        XCTAssertEqual(opened.expiresAt, now + 3600)
        XCTAssertThrowsError(try Share.open(short, code: code, now: now + 3600)) {
            XCTAssertEqual(($0 as? ShareError)?.reason, "expired")
        }
        let capped = try Share.seal(item: item, code: code, sender: "iPhone", now: now, expires: now + 10 * 86400)
        XCTAssertEqual(try Share.open(capped, code: code, now: now).expiresAt, now + Share.lifetime)
        XCTAssertThrowsError(try Share.seal(item: item, code: code, sender: "iPhone", now: now, expires: now)) {
            XCTAssertEqual(($0 as? ShareError)?.reason, "malformed")
        }

        XCTAssertThrowsError(try Share.open(plain, code: code, now: now, revoked: [packageID])) {
            XCTAssertEqual(($0 as? ShareError)?.reason, "revoked")
        }
        XCTAssertThrowsError(try Share.open(plain, code: "zoo zoo zoo zoo zoo zoo", now: now, revoked: [packageID])) {
            XCTAssertEqual(($0 as? ShareError)?.reason, "wrong-code")
        }
    }
}
