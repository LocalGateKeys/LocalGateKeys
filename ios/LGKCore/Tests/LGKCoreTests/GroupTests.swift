import XCTest
import Foundation
import Crypto
@testable import LGKCore

/// `scripts/make_sync_vectors.py` DetRand: sha256(b"lgk-sync-vectors|rand|" + label + b"|" + counter_be32)
/// blocks; each call starts a fresh block and drops the unused tail.
final class DetRand: RandomSource, @unchecked Sendable {
    private let label: [UInt8]
    private var counter: UInt32 = 0
    private let lock = NSLock()
    init(_ label: String) { self.label = Array("lgk-sync-vectors|rand|\(label)".utf8) }
    func bytes(count: Int) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        var out = [UInt8]()
        while out.count < count {
            let c = [UInt8(counter >> 24), UInt8((counter >> 16) & 0xFF), UInt8((counter >> 8) & 0xFF), UInt8(counter & 0xFF)]
            out += Array(SHA256.hash(data: label + Array("|".utf8) + c))
            counter += 1
        }
        return Array(out.prefix(count))
    }
}

/// Returns the same bytes on every call.
struct FixedRandom: RandomSource {
    let value: [UInt8]
    func bytes(count: Int) -> [UInt8] { Array(value.prefix(count)) }
}

struct FixedClock: UnixClock { let now: Int64 }

final class GroupTests: XCTestCase {
    static let groupID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
    static let devices: [(name: String, id: String, counter: Int64, written: Int64)] = [
        ("A", EngineTests.A, 7, 900), ("B", EngineTests.B, 4, 880), ("C", EngineTests.C, 3, 860),
    ]

    // MARK: helpers

    func epoch1Hex(_ field: String) throws -> String {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("expected.json"))),
              case .object(let epochs)? = o["epochs"], case .object(let e1)? = epochs["1"],
              case .string(let hex)? = e1[field] else { throw JSONError.syntax }
        return hex
    }

    func key() throws -> GroupKey {
        try GroupKey(groupID: Self.groupID, epoch: 1, key: Vectors.hex(epoch1Hex("group_key_hex")))
    }

    func file(_ name: String) throws -> [UInt8] { Array(try Vectors.data("devices/\(name).lgksync")) }

    func decodeAll() throws -> [String: (header: ViewHeader, states: [ItemState])] {
        let gk = try key()
        var out: [String: (header: ViewHeader, states: [ItemState])] = [:]
        for d in Self.devices { out[d.name] = try ViewFile.decode(try file(d.name), key: gk, expectedDeviceID: d.id) }
        return out
    }

    func reason(_ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) -> String? {
        do { _ = try body(); XCTFail("expected SyncFormatError", file: file, line: line); return nil } catch let e as SyncFormatError {
            return e.reason
        } catch { XCTFail("unexpected \(error)", file: file, line: line); return nil }
    }

    /// Splits a view into (header line bytes, sealed records), decrypting with the vector file key.
    func split(_ raw: [UInt8]) throws -> ([UInt8], [JSONValue]) {
        let magic = ViewFile.magic.count
        let end = raw[magic...].firstIndex(of: 0x0A)!
        let header = Array(raw[magic..<end])
        let blob = Array(raw[(end + 1)...])
        let plain = try CryptoBox.openGCM(key: Vectors.hex(epoch1Hex("file_key_hex")), nonce: Array(blob[..<12]),
                                          ciphertext: Array(blob[12...]), aad: header)
        guard case .array(let recs) = try CanonicalJSON.parse(plain) else { throw JSONError.syntax }
        return (header, recs)
    }

    /// Re-seals `records` under `header` with the vector file key (an attacker holding the file key).
    func rewrap(_ header: [UInt8], _ records: [JSONValue]) throws -> [UInt8] {
        let nonce = [UInt8](repeating: 7, count: 12)
        let body = try CryptoBox.sealGCM(key: Vectors.hex(epoch1Hex("file_key_hex")), nonce: nonce,
                                         plaintext: CanonicalJSON.encode(.array(records), dialect: .utf8), aad: header)
        return ViewFile.magic + header + [0x0A] + nonce + body
    }

    func withField(_ rec: JSONValue, _ k: String, _ v: JSONValue?) -> JSONValue {
        var o = MergeVectors.obj(rec); o[k] = v; return .object(o)
    }

    // MARK: keys

    func test_record_and_file_keys_match_vectors() throws {
        let gk = try key()
        XCTAssertEqual(Vectors.hexString(gk.recordKey), try epoch1Hex("record_key_hex"))
        XCTAssertEqual(Vectors.hexString(gk.fileKey), try epoch1Hex("file_key_hex"))
        XCTAssertEqual(Vectors.hexString(ViewFile.magic), "4c474b53594e43310a")
        XCTAssertEqual(reason { try GroupKey(groupID: "bad id", epoch: 1, key: [UInt8](repeating: 0, count: 32)) }, "bad-group-key")
        XCTAssertEqual(reason { try GroupKey(groupID: "g", epoch: 0, key: [UInt8](repeating: 0, count: 32)) }, "bad-group-key")
        XCTAssertEqual(reason { try GroupKey(groupID: "g", epoch: 1, key: [1, 2]) }, "bad-group-key")
    }

    // MARK: device files

    func test_decode_device_files_A_B_C() throws {
        let views = try decodeAll()
        let inputs = try MergeVectors.deviceStates()
        // States every other device dominates carry placeholder content in MergeVectors.
        let placeholders: Set<[String]> = [["A", EngineTests.LOGIN_DELETED], ["A", EngineTests.BOOKMARK],
                                           ["B", EngineTests.LOGIN_DELETED],
                                           ["C", EngineTests.LOGIN_EDITED], ["C", EngineTests.LOGIN_TIE]]
        for d in Self.devices {
            let v = views[d.name]!
            XCTAssertEqual(v.header, ViewHeader(format: 1, groupID: Self.groupID, deviceID: d.id, epoch: 1,
                                                counter: d.counter, writtenAt: EngineTests.T0 + d.written))
            let want = inputs[d.name]!.sorted { $0.itemID < $1.itemID }
            XCTAssertEqual(v.states.map(\.itemID), want.map(\.itemID), d.name)
            for (got, exp) in zip(v.states, want) {
                XCTAssertEqual(got.vv, exp.vv, "\(d.name) \(got.itemID)")
                XCTAssertEqual(got.deleted, exp.deleted)
                XCTAssertEqual(got.deletedAt, exp.deletedAt)
                if placeholders.contains([d.name, got.itemID]) {
                    XCTAssertNotNil(got.item)
                } else {
                    XCTAssertEqual(got, exp, "\(d.name) \(got.itemID)")
                }
            }
        }
    }

    func test_decoded_device_files_merge_in_all_six_orders() throws {
        let views = try decodeAll().mapValues(\.states)
        let expected = try MergeVectors.arr(MergeVectors.expectedMerge()["engine_states"]).map(MergeVectors.state)
        let orders = [["A", "B", "C"], ["A", "C", "B"], ["B", "A", "C"], ["B", "C", "A"], ["C", "A", "B"], ["C", "B", "A"]]
        for order in orders {
            var local = Dictionary(uniqueKeysWithValues: views[order[0]]!.map { ($0.itemID, $0) })
            for name in order.dropFirst() {
                let out = try Engine.merge(local: local, remote: views[name]!)
                for s in out.upserts + out.deletes + out.copies { local[s.itemID] = s }
            }
            let got = local.values.sorted { $0.itemID < $1.itemID }
            XCTAssertEqual(got, expected, order.joined())
            for (g, e) in zip(got, expected) where g.item != nil {
                XCTAssertEqual(try CanonicalJSON.encode(g.item!, dialect: .utf8), try CanonicalJSON.encode(e.item!, dialect: .utf8))
            }
        }
    }

    func test_reencode_with_vector_nonces_is_byte_identical() throws {
        let gk = try key()
        let views = try decodeAll()
        for d in Self.devices {
            let v = views[d.name]!
            let out = try ViewFile.encode(key: gk, deviceID: d.id, counter: d.counter, states: v.states.reversed(),
                                          now: FixedClock(now: EngineTests.T0 + d.written), random: DetRand("view|\(d.name)"))
            XCTAssertEqual(out, try file(d.name), d.name)
        }
    }

    func test_encode_decode_round_trip_and_encode_errors() throws {
        let gk = try key()
        let states = try decodeAll()["B"]!.states
        let raw = try ViewFile.encode(key: gk, deviceID: "phone-1", counter: 2, states: states,
                                      now: FixedClock(now: 5), random: SystemRandomSource())
        let back = try ViewFile.decode(raw, key: gk, expectedDeviceID: nil)
        XCTAssertEqual(back.states, states)
        XCTAssertEqual(back.header.deviceID, "phone-1")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "phone-1", counter: 2, states: states,
                                                    now: FixedClock(now: 5), random: FixedRandom(value: Array(repeating: 1, count: 12))) },
                       "nonce-reuse")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "phone-1", counter: 2, states: [states[0], states[0]],
                                                    now: FixedClock(now: 5), random: SystemRandomSource()) }, "duplicate-id")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "phone 1", counter: 2, states: states,
                                                    now: FixedClock(now: 5), random: SystemRandomSource()) }, "bad-header")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "p", counter: -1, states: states,
                                                    now: FixedClock(now: 5), random: SystemRandomSource()) }, "bad-header")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "p", counter: 1, states: states,
                                                    now: FixedClock(now: 5), random: SystemRandomSource(), maxRecords: 2) }, "too-many-records")
        XCTAssertEqual(reason { try ViewFile.encode(key: gk, deviceID: "p", counter: 1, states: states,
                                                    now: FixedClock(now: 5), random: FixedRandom(value: [1])) }, "bad-nonce")
        // Empty view still round-trips.
        let empty = try ViewFile.encode(key: gk, deviceID: "p", counter: 0, states: [], now: FixedClock(now: 0), random: SystemRandomSource())
        XCTAssertEqual(try ViewFile.decode(empty, key: gk, expectedDeviceID: "p").states, [])
    }

    // MARK: tampering

    func test_tampered_header_and_body() throws {
        let gk = try key()
        let raw = try file("A")
        let m = ViewFile.magic.count
        let headerEnd = raw[m...].firstIndex(of: 0x0A)!
        let header = String(decoding: raw[m..<headerEnd], as: UTF8.self)
        func flip(_ i: Int, _ to: UInt8? = nil) -> [UInt8] { var r = raw; r[i] = to ?? (r[i] ^ 0x01); return r }
        func withHeader(_ h: String) -> [UInt8] { ViewFile.magic + Array(h.utf8) + Array(raw[headerEnd...]) }
        func dec(_ r: [UInt8], _ k: GroupKey? = nil, _ dev: String? = EngineTests.A) -> () throws -> Any {
            { try ViewFile.decode(r, key: k ?? gk, expectedDeviceID: dev) }
        }

        XCTAssertEqual(reason(dec(flip(0))), "bad-magic")
        XCTAssertEqual(reason(dec(flip(m))), "bad-header")                       // '{' -> 'z'
        XCTAssertEqual(reason(dec(Array(raw[..<headerEnd]))), "bad-header")      // no newline
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"counter\":7", with: "\"counter\":8")))), "auth-failed")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"counter\":7", with: "\"counter\": 7")))), "header-noncanonical")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"counter\":7", with: "\"counter\":7.0")))), "bad-header")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"counter\":7", with: "\"counter\":true")))), "bad-header")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"format\":1", with: "\"format\":2")))), "bad-header")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: "\"epoch\":1", with: "\"epoch\":2")))), "epoch-mismatch")
        XCTAssertEqual(reason(dec(withHeader(header.replacingOccurrences(of: Self.groupID, with: "other-group")))), "group-mismatch")
        XCTAssertEqual(reason(dec(raw, nil, EngineTests.B)), "device-mismatch")
        XCTAssertEqual(reason(dec(raw, try GroupKey(groupID: Self.groupID, epoch: 1, key: [UInt8](repeating: 9, count: 32)))), "auth-failed")
        XCTAssertEqual(reason(dec(flip(headerEnd + 1))), "auth-failed")          // nonce byte
        XCTAssertEqual(reason(dec(flip(raw.count / 2 + headerEnd / 2))), "auth-failed") // body byte
        XCTAssertEqual(reason(dec(flip(raw.count - 1))), "auth-failed")          // tag byte
        XCTAssertEqual(reason(dec(Array(raw[...(headerEnd + 27)]))), "bad-payload")
        XCTAssertEqual(reason { try ViewFile.decode(raw, key: gk, expectedDeviceID: nil, maxBytes: raw.count - 1) }, "too-large")
        XCTAssertEqual(reason { try ViewFile.decode(raw, key: gk, expectedDeviceID: nil, maxRecords: 2) }, "too-many-records")
    }

    func test_tampered_records() throws {
        let gk = try key()
        let (header, recs) = try split(try file("C"))
        XCTAssertNoThrow(try ViewFile.decode(try rewrap(header, recs), key: gk, expectedDeviceID: nil))
        let live = recs[0]                                  // 11111111 live
        let tomb = recs.first { MergeVectors.obj($0)["deleted"] == .bool(true) }!
        func check(_ r: [JSONValue], _ want: String, line: UInt = #line) {
            XCTAssertEqual(reason({ try ViewFile.decode(try self.rewrap(header, r), key: gk, expectedDeviceID: nil) }, line: line), want, line: line)
        }
        func ct(_ rec: JSONValue) -> [UInt8] { try! Base64.decodeStrict(MergeVectors.str(MergeVectors.obj(rec)["ct"])!) }
        var flipped = ct(live); flipped[20] ^= 1

        check([live, live], "duplicate-id")
        check([.string("x")], "bad-payload")
        check([withField(live, "extra", .null)], "bad-fields")
        check([withField(live, "ct", nil)], "bad-fields")
        check([withField(live, "deleted", .int(0))], "bad-fields")
        check([withField(live, "deleted_at", .int(-1))], "bad-fields")
        check([withField(live, "ct", .int(1))], "bad-fields")
        check([withField(live, "id", .string("not valid"))], "invalid-state")
        check([withField(live, "vv", .object(["a": .bool(true)]))], "invalid-state")
        check([withField(live, "ct", .string(""))], "empty-ct")
        check([withField(live, "deleted_at", .int(5))], "invalid-state")
        check([withField(live, "ct", .string("AAAA="))], "bad-ct")
        check([withField(live, "ct", .string("AAAA"))], "bad-ct")
        check([withField(live, "ct", .string(Base64.encode(flipped)))], "auth-failed")
        check([withField(live, "vv", .object([EngineTests.A: .int(9)]))], "auth-failed")
        check([withField(tomb, "deleted_at", .int(1))], "auth-failed")
        check([withField(live, "id", .string("99999999-aaaa-4000-8000-000000000009"))], "auth-failed")

        // A key holder sealing bad plaintexts.
        func sealed(_ id: String, _ deleted: Bool, _ plain: [UInt8]) throws -> JSONValue {
            let aad = try CanonicalJSON.encode(.object(["label": .string("lgk-sync-item-v1"), "id": .string(id),
                                                        "vv": .object(["a": .int(1)]), "deleted": .bool(deleted),
                                                        "deleted_at": deleted ? .int(1) : .null, "epoch": .int(1)]), dialect: .utf8)
            let nonce = [UInt8](repeating: 3, count: 12)
            let body = try CryptoBox.sealGCM(key: gk.recordKey, nonce: nonce, plaintext: plain, aad: aad)
            return .object(["id": .string(id), "vv": .object(["a": .int(1)]), "deleted": .bool(deleted),
                            "deleted_at": deleted ? .int(1) : .null, "ct": .string(Base64.encode(nonce + body))])
        }
        check([try sealed("i", true, [0x7B, 0x7D])], "bad-item")
        check([try sealed("i", false, Array("[1]".utf8))], "bad-item")
        check([try sealed("i", false, Array("{".utf8))], "bad-item")
        check([try sealed("i", false, Array("{\"a\":1,\"a\":2}".utf8))], "bad-item")
        check([try sealed("i", false, Array("{\"id\":\"j\"}".utf8))], "id-mismatch")
        check([try sealed("i", false, Array("{\"record\":{\"id\":\"j\"}}".utf8))], "id-mismatch")
        XCTAssertNoThrow(try ViewFile.decode(try rewrap(header, [try sealed("i", false, Array("{\"id\":\"i\",\"record\":{\"id\":\"j\"}}".utf8))]),
                                             key: gk, expectedDeviceID: nil))
        let ok = try ViewFile.decode(try rewrap(header, [try sealed("i", true, [])]), key: gk, expectedDeviceID: nil)
        XCTAssertEqual(ok.states, [try ItemState(itemID: "i", vv: ["a": 1], deleted: true, deletedAt: 1, item: nil)])
    }
}
