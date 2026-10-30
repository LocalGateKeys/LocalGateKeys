import XCTest
@testable import LGKCore

/// `.lgkshare` v1 against `tests/vectors/share/v1.json` (desktop `share.py`), byte for byte.
final class ShareTests: XCTestCase {
    private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    private func int(_ v: JSONValue?) -> Int64 { if case .int(let i)? = v { return i }; return -1 }

    func vectors() throws -> [String: JSONValue] {
        obj(try CanonicalJSON.parse(Array(try Vectors.data("../share/v1.json"))))
    }

    func testSealMatchesTheVectorsByteForByte() throws {
        let opens = arr(try vectors()["opens"]) + arr(try vectors()["legacy"])
        XCTAssertFalse(opens.isEmpty)
        for v in opens {
            let c = obj(v)
            let data = try Share.seal(item: obj(c["item"]), code: str(c["code"]), sender: str(c["sender"]), now: int(c["now"]),
                                      packageID: str(c["id"]), salt: try Base64.decodeStrict(str(c["salt"])),
                                      nonce: try Base64.decodeStrict(str(c["nonce"])))
            XCTAssertEqual(String(decoding: data, as: UTF8.self), str(c["package"]), str(c["name"]))
        }
    }

    func testOpenReturnsTheItem() throws {
        for v in arr(try vectors()["opens"]) {
            let c = obj(v)
            let opened = try Share.open(Array(str(c["package"]).utf8), code: str(c["code"]), now: int(c["now"]))
            XCTAssertEqual(opened.item, obj(c["item"]), str(c["name"]))
            XCTAssertEqual(opened.id, str(c["id"]))
            XCTAssertEqual(opened.sender, str(c["sender"]))
            XCTAssertEqual(opened.expiresAt, opened.createdAt + Share.lifetime)
            // Open once.
            XCTAssertThrowsError(try Share.open(Array(str(c["package"]).utf8), code: str(c["code"]), now: int(c["now"]),
                                                opened: [opened.id])) {
                XCTAssertEqual(($0 as? ShareError)?.reason, "already-opened")
            }
        }
    }

    /// Items shared from Windows, Android, iPhone and Mac (the stored shape) reach the vault's normal form;
    /// a desktop login is refused here (`phone_saves: false`).
    func testEveryVectorItemConvertsToTheVaultForm() throws {
        let id = "11111111-2222-4333-8444-555555555555"
        for v in arr(try vectors()["opens"]) {
            let c = obj(v)
            let opened = try Share.open(Array(str(c["package"]).utf8), code: str(c["code"]), now: int(c["now"]))
            guard c["phone_saves"] == .bool(true) else {
                XCTAssertThrowsError(try Share.vaultForm(opened.item, id: id, now: int(c["now"])), str(c["name"]))
                continue
            }
            let (ns, normal) = try Share.vaultForm(opened.item, id: id, now: int(c["now"]))
            let rec = obj(normal)
            XCTAssertEqual(rec["id"], .string(id), str(c["name"]))
            XCTAssertEqual(rec["favorite"], .bool(false))
            XCTAssertEqual(rec["kind"], obj(c["item"])["kind"])
            switch str(c["name"]) {
            case "login":
                XCTAssertEqual(ns, .entry)
                XCTAssertEqual(obj(rec["scope"])["origin"], .string("https://alpha.test"))
                XCTAssertEqual(arr(obj(rec["scope"])["urls"]).map { obj($0)["match"] },
                               [.string("exact_origin"), .string("starts_with"), .string("host")])
                XCTAssertEqual(rec["label"], .string("Alpha"))
                XCTAssertEqual(rec["password"], .string("pw-alpha-1234567"))
            case "wifi":
                XCTAssertEqual(ns, .item)
                XCTAssertEqual(obj(rec["payload"])["ssid"], .string("Home"))
                XCTAssertEqual(obj(rec["payload"])["security"], .string("wpa2"))
            default:
                XCTAssertEqual(ns, .item)
                XCTAssertEqual(rec["title"], obj(c["item"])["title"])
            }
        }
        // Early builds sent the display shape: converted, then saved.
        for v in arr(try vectors()["legacy"]) {
            let c = obj(v)
            let opened = try Share.open(Array(str(c["package"]).utf8), code: str(c["code"]), now: int(c["now"]))
            let (_, normal) = try Share.vaultForm(opened.item, id: id, now: int(c["now"]))
            let stored = obj(c["stored"])
            if case .object(let scope)? = stored["scope"] {
                XCTAssertEqual(obj(obj(normal)["scope"])["origin"], scope["origin"])
            } else {
                XCTAssertEqual(obj(obj(normal)["payload"])["ssid"], obj(stored["payload"])["ssid"])
            }
        }
        XCTAssertThrowsError(try Share.vaultForm(["kind": .string("desktop"), "label": .string("x")], id: id, now: 1))
        XCTAssertThrowsError(try Share.vaultForm(["kind": .string("document"), "title": .string("x")], id: id, now: 1))
    }

    func testRefusedVectors() throws {
        let refused = arr(try vectors()["refused"])
        XCTAssertFalse(refused.isEmpty)
        for v in refused {
            let c = obj(v)
            XCTAssertThrowsError(try Share.open(Array(str(c["package"]).utf8), code: str(c["code"]), now: int(c["now"])),
                                 str(c["name"])) {
                XCTAssertEqual(($0 as? ShareError)?.reason, str(c["reason"]), str(c["name"]))
            }
        }
    }

    func testCodeNormalisationAndQR() throws {
        XCTAssertEqual(try Share.normalizeCode("  Maple-river·onion. seven,lamp   QUOTE "), "maple river onion seven lamp quote")
        XCTAssertThrowsError(try Share.normalizeCode("maple river onion seven lamp notaword"))
        XCTAssertThrowsError(try Share.normalizeCode("maple river onion seven lamp quote quote"))
        let qr = try Share.codeQRText("maple river onion seven lamp quote")
        XCTAssertEqual(qr, "lgkshare-code:maple-river-onion-seven-lamp-quote")
        XCTAssertEqual(try Share.code(fromQRText: qr), "maple river onion seven lamp quote")
        XCTAssertThrowsError(try Share.code(fromQRText: "lgk-pair:abc"))
        let code = try Share.generateCode()
        XCTAssertEqual(try Share.normalizeCode(code), code)
        XCTAssertEqual(code.split(separator: " ").count, 6)
    }

    func testPasskeysAndAttachmentsCannotBeShared() throws {
        XCTAssertFalse(Share.canShare(["kind": .string("passkey")]))
        XCTAssertFalse(Share.canShare(["kind": .string("note"), "attachment_ids": .array([.string("a")])]))
        XCTAssertTrue(Share.canShare(["kind": .string("note"), "attachment_ids": .array([])]))
        XCTAssertThrowsError(try Share.seal(item: ["kind": .string("passkey")], code: "maple river onion seven lamp quote",
                                            sender: "x", now: 1)) {
            XCTAssertEqual(($0 as? ShareError)?.reason, "not-shareable")
        }
    }

    func testLocalOnlyKeysAreDroppedAndRoundTrip() throws {
        let item: [String: JSONValue] = ["kind": .string("note"), "title": .string("Ünïcode ✓"), "favorite": .bool(true),
                                         "password_history": .array([.string("old")])]
        let code = "maple river onion seven lamp quote"
        let data = try Share.seal(item: item, code: code, sender: "  Desk PC  ", now: 1_800_000_000)
        XCTAssertTrue(Share.fitsQR(data))
        let header = try Share.readHeader(data)
        XCTAssertEqual(header.sender, "Desk PC")
        let opened = try Share.open(data, code: code, now: 1_800_000_010)
        XCTAssertEqual(opened.item, ["kind": .string("note"), "title": .string("Ünïcode ✓")])
    }
}
