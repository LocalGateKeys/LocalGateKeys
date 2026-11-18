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

    /// Sub-plan 06: the send order travels with the message; the stored copy (no sequence) keeps its old bytes.
    func testSequenceRoundTripAndStoredFormat() throws {
        let c = WatchCode(id: "a", title: "A", secret: rfcSecret)
        let sent = try WatchMessage.sequenced(from: try WatchMessage.replace([c]).userInfo(sequence: 42))
        XCTAssertEqual(sent.message, .replace([c]))
        XCTAssertEqual(sent.sequence, 42)
        XCTAssertEqual(try WatchMessage.decodeSequenced(try WatchMessage.forget.encoded(sequence: 7)).sequence, 7)
        let stored = try WatchMessage.replace([c]).encoded()
        XCTAssertFalse(String(decoding: stored, as: UTF8.self).contains("seq"))
        XCTAssertNil(try WatchMessage.decodeSequenced(stored).sequence)
        XCTAssertEqual(try WatchMessage.decodeSequenced(Data(#"{"v":1,"op":"forget"}"#.utf8)).message, .forget)
    }

    func testNextSequenceAlwaysRises() {
        let now = Date(timeIntervalSince1970: 1_767_225_610)
        XCTAssertEqual(WatchMessage.nextSequence(after: 0, now: now), 1_767_225_610_000)
        // The clock went back: still above the last one.
        XCTAssertEqual(WatchMessage.nextSequence(after: 1_767_225_610_000, now: now.addingTimeInterval(-3600)),
                       1_767_225_610_001)
        XCTAssertEqual(WatchMessage.nextSequence(after: 5, now: Date(timeIntervalSince1970: .nan)), 6)
        XCTAssertEqual(WatchMessage.nextSequence(after: .max, now: now), .max)
    }

    func testOlderMessageIsStale() {
        XCTAssertTrue(WatchMessage.isStale(sequence: 2, lastApplied: 3))
        XCTAssertTrue(WatchMessage.isStale(sequence: 3, lastApplied: 3), "a repeat is not applied twice")
        XCTAssertFalse(WatchMessage.isStale(sequence: 4, lastApplied: 3))
        XCTAssertFalse(WatchMessage.isStale(sequence: 1, lastApplied: nil))
        XCTAssertFalse(WatchMessage.isStale(sequence: nil, lastApplied: 3), "an older iPhone build is applied as before")
    }

    /// Fix round 2: a forget is applied whatever its order and resets it, so an iPhone whose order went back
    /// (reinstall, new phone, lost counter) is not locked out; an implausible stored order is dropped.
    func testForgetAlwaysAppliesAndResetsTheOrder() {
        let now = Date(timeIntervalSince1970: 1_767_225_610)
        let c = WatchCode(id: "a", title: "A", secret: rfcSecret)
        let forget = WatchMessage.ordering(of: .forget, sequence: 5, lastApplied: 1_767_225_000_000, now: now)
        XCTAssertTrue(forget.apply, "a forget with an order below the last one still clears")
        XCTAssertEqual(forget.lastApplied, 5)
        let next = WatchMessage.ordering(of: .replace([c]), sequence: 6, lastApplied: forget.lastApplied, now: now)
        XCTAssertTrue(next.apply, "the update after that forget is accepted")
        XCTAssertEqual(next.lastApplied, 6)
        let late = WatchMessage.ordering(of: .replace([c]), sequence: 4, lastApplied: 5, now: now)
        XCTAssertFalse(late.apply)
        XCTAssertEqual(late.lastApplied, 5)
        let unordered = WatchMessage.ordering(of: .forget, sequence: nil, lastApplied: 5, now: now)
        XCTAssertTrue(unordered.apply)
        XCTAssertEqual(unordered.lastApplied, 5)
    }

    func testImplausibleStoredOrderIsDropped() {
        let now = Date(timeIntervalSince1970: 1_767_225_610)
        let c = WatchCode(id: "a", title: "A", secret: rfcSecret)
        for bad: Int64 in [.max, -1, 1_767_225_610_000 + 2 * 86_400_000] {
            let r = WatchMessage.ordering(of: .replace([c]), sequence: 7, lastApplied: bad, now: now)
            XCTAssertTrue(r.apply, "\(bad)")
            XCTAssertEqual(r.lastApplied, 7)
        }
        XCTAssertEqual(WatchMessage.plausible(1_767_225_610_000, now: now), 1_767_225_610_000)
        XCTAssertNil(WatchMessage.plausible(.max, now: now))
    }
}
