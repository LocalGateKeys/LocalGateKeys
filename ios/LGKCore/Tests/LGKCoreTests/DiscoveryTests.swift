import XCTest
@testable import LGKCore

/// `tests/vectors/sync/discovery.json` (desktop `sync.discovery`, Android `DiscoveryTest`).
final class DiscoveryTests: XCTestCase {
    var v: [String: Any]!
    var groupKey: GroupKey!
    var host: String!

    override func setUpWithError() throws {
        v = try Vectors.json("discovery.json")
        let key = try XCTUnwrap(Data(base64Encoded: v["group_key_b64"] as! String))
        groupKey = try GroupKey(groupID: v["group_id"] as! String, epoch: Int64(v["epoch"] as! Int), key: Array(key))
        host = v["host_device_id"] as? String
    }

    func test_discovery_key_and_service_type() throws {
        XCTAssertEqual(Data(Discovery.discoveryKey(groupKey)).base64EncodedString(), v["discovery_key_b64"] as? String)
        XCTAssertEqual(Discovery.serviceType, v["service_type"] as? String)
    }

    func test_tags_for_fixed_days() throws {
        let tags = try XCTUnwrap(v["tags"] as? [[String: String]])
        XCTAssertFalse(tags.isEmpty)
        for t in tags {
            XCTAssertEqual(Discovery.tag(groupKey, hostDeviceID: host, day: t["day"]!), t["tag"], t["day"]!)
        }
    }

    func test_window_and_txt() throws {
        let window = try XCTUnwrap(v["window"] as? [String: Any])
        let now = Int64(window["now"] as! Int)
        XCTAssertEqual(Discovery.acceptedTags(groupKey, hostDeviceID: host, now: now), Set(window["accepted"] as! [String]))
        XCTAssertEqual(Discovery.txtRecord(groupKey, hostDeviceID: host, now: now), v["txt"] as? [String: String])
    }

    func test_utc_day_and_instance_name() {
        XCTAssertEqual(Discovery.utcDay(0), "1970-01-01")
        XCTAssertEqual(Discovery.utcDay(1_790_003_600), Discovery.utcDay(1_790_003_600 - 1_790_003_600 % 86_400))
        let name = Discovery.instanceName(random: FixedRandom(value: [0x3f, 0x9a]))
        XCTAssertEqual(name, v["instance_name_example"] as? String)
    }

    func test_candidates_filter_dedupe_and_cap() throws {
        let accepted: Set<String> = ["good"]
        let pinned = try LanEndpoint(validating: "192.168.1.20", port: 47821)
        func a(_ h: String, _ p: Int = 47821, v: String = "1", t: String? = "good") -> Discovery.Announcement {
            var txt = ["v": v]; if let t { txt["t"] = t }
            return Discovery.Announcement(host: h, port: p, txt: txt)
        }
        let found = [
            a("192.168.1.20"),                 // the pinned address: already tried
            a("192.168.1.30", t: "wrong"),     // another group's or another host's tag
            a("192.168.1.31", v: "2"),         // unknown version
            a("192.168.1.32", t: nil),
            a("8.8.8.8"),                      // not a LAN address
            a("127.0.0.1"), a("169.254.1.2"), a("0.1.2.3"), a("fe80::1"), a("fd00::1"),
            a("192.168.1.40", 0), a("192.168.1.40", 70_000),
            a("192.168.1.41"), a("192.168.1.41"),   // duplicate
            a("10.0.0.2"), a("172.16.0.3"), a("192.168.1.42"), a("192.168.1.43"),
        ]
        let out = Discovery.candidates(found, accepted: accepted, alreadyTried: pinned)
        XCTAssertEqual(out.map(\.host), ["192.168.1.41", "10.0.0.2", "172.16.0.3", "192.168.1.42"])
        XCTAssertEqual(out.count, Discovery.maxCandidates)
    }

    func test_routable() {
        for ok in ["192.168.1.2", "10.0.0.1", "172.31.255.255"] { XCTAssertTrue(Discovery.routable(ok), ok) }
        for bad in ["127.0.0.1", "0.0.0.0", "169.254.0.1", "fe80::1", "1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3", "1234.1.1.1"] {
            XCTAssertFalse(Discovery.routable(bad), bad)
        }
    }
}
