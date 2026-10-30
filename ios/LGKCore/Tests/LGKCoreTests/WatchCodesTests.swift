import XCTest
@testable import LGKCore

/// UX workstream 12: pinned 2FA codes for the watch.
final class WatchCodesTests: XCTestCase {
    /// RFC 6238 SHA1 seed "12345678901234567890" in Base32.
    let rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    func login(_ id: String, title: String, totp: JSONValue?) -> JSONValue {
        var r: [String: JSONValue] = ["id": .string(id), "kind": .string("web"), "title": .string(title),
                                      "username": .string("alice"), "password": .string("pw")]
        if let totp { r["totp"] = totp }
        return Wrapper.make(ns: .entry, record: .object(r))
    }

    func snapshot() -> StoreSnapshot {
        let deleted = SyncMeta(digest: nil, body: nil, updatedAt: 1, vv: [:], deleted: true, deletedAt: 1)
        return StoreSnapshot(records: [
            "a": login("a", title: "GitHub", totp: .object(["secret": .string(rfcSecret), "digits": .int(8)])),
            "b": login("b", title: "Bank", totp: nil),
            "c": login("c", title: "Gone", totp: .object(["secret": .string(rfcSecret)])),
            "d": login("d", title: "Mail", totp: .object(["secret": .string(rfcSecret), "algorithm": .string("SHA1")])),
        ], meta: ["c": deleted], revision: 1)
    }

    func testCodesMatchRFC6238() {
        let codes = WatchPins.codes(pins: ["a"], snapshot: snapshot())
        XCTAssertEqual(codes.first?.current(at: 59)?.code, "94287082")
        XCTAssertEqual(codes.first?.current(at: 1111111109)?.code, "07081804")
        XCTAssertEqual(codes.first?.current(at: 59)?.secondsRemaining, 1)
        XCTAssertEqual(codes.first?.current(at: 60)?.secondsRemaining, 30)
    }

    func testOnlyLivePinnedItemsWithASecretInPinOrder() {
        let codes = WatchPins.codes(pins: ["d", "b", "c", "a"], snapshot: snapshot())
        XCTAssertEqual(codes.map(\.id), ["d", "a"])
        XCTAssertEqual(codes.map(\.title), ["Mail", "GitHub"])
    }

    func testMessageCarriesNoPasswordOrUsername() throws {
        let data = try WatchMessage.replace(WatchPins.codes(pins: ["a"], snapshot: snapshot())).encoded()
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(text.contains("alice"))
        XCTAssertFalse(text.contains("\"pw\""))
    }

    func testUnpinRemovesTheSecretFromTheNextMessage() throws {
        var pins = ["a", "d"]
        pins = try XCTUnwrap(WatchPins.toggle("a", in: pins))
        XCTAssertEqual(pins, ["d"])
        let msg = try WatchMessage.decode(WatchMessage.replace(WatchPins.codes(pins: pins, snapshot: snapshot())).encoded())
        guard case .replace(let codes) = msg else { return XCTFail("replace expected") }
        XCTAssertEqual(codes.map(\.id), ["d"])
    }

    func testPinLimitOfTen() throws {
        let ten = (0..<10).map { "i\($0)" }
        XCTAssertNil(WatchPins.toggle("x", in: ten))
        XCTAssertEqual(WatchPins.toggle("i3", in: ten)?.count, 9)
        let eleven = (0..<11).map { WatchCode(id: "i\($0)", title: "", secret: rfcSecret) }
        XCTAssertThrowsError(try WatchMessage.replace(eleven).encoded())
    }

    func testForgetAndMalformedMessages() throws {
        XCTAssertEqual(try WatchMessage.from(userInfo: try WatchMessage.forget.userInfo()), .forget)
        XCTAssertThrowsError(try WatchMessage.decode(Data("{}".utf8)))
        XCTAssertThrowsError(try WatchMessage.decode(Data(#"{"v":2,"op":"forget"}"#.utf8)))
        XCTAssertThrowsError(try WatchMessage.from(userInfo: ["other": Data()]))
        let dup = [WatchCode(id: "a", title: "", secret: rfcSecret), WatchCode(id: "a", title: "", secret: rfcSecret)]
        let wire = #"{"v":1,"op":"replace","codes":\#(String(decoding: try JSONEncoder().encode(dup), as: UTF8.self))}"#
        XCTAssertThrowsError(try WatchMessage.decode(Data(wire.utf8)), "duplicate ids are refused")
    }
}
