import XCTest
@testable import LGKCore

final class ActivityChainTests: XCTestCase {
    // The same vector as tests/test_activity_chain.py::test_shared_vector (Windows activity.py).
    private let first = ActivityChain.Event(id: "00000000-0000-4000-8000-000000000001", eventType: "agent.request",
                                            timestamp: 1_762_905_600, prevHash: ActivityChain.genesis)
    private let firstHash = "a41a74612fea40f020a620bfc5388089682665bc54d23e81c8b379376f6dc1c8"
    private let secondHash = "c524dbc6cca86059dab754117ff3de604fe472e98eef5493f9ca68e39dcf4012"

    private var second: ActivityChain.Event {
        ActivityChain.Event(id: "00000000-0000-4000-8000-000000000002", eventType: "agent.fill", timestamp: 1_762_905_601,
                            itemID: "00000000-0000-4000-8000-0000000000aa", count: 1, prevHash: firstHash)
    }

    func testSharedVectorMatchesWindows() {
        XCTAssertEqual(ActivityChain.hash(first), firstHash)
        XCTAssertEqual(ActivityChain.hash(second), secondHash)
        XCTAssertEqual(ActivityChain.link(after: [first]), firstHash)
    }

    func testVerifyFindsTamperingAndHonoursCheckpoint() {
        XCTAssertTrue(ActivityChain.verify([first, second], head: secondHash).ok)
        var tampered = first
        tampered.result = "denied"
        XCTAssertEqual(ActivityChain.verify([tampered, second]).firstBadID, first.id)
        XCTAssertFalse(ActivityChain.verify([first, second], head: firstHash).ok)
        XCTAssertTrue(ActivityChain.verify([second], checkpoint: firstHash).ok)
        XCTAssertFalse(ActivityChain.verify([second]).ok)
    }

    func testTruncationAndEmptyingAreCaughtByTheHead() {
        XCTAssertFalse(ActivityChain.verify([first], head: secondHash).ok)
        XCTAssertFalse(ActivityChain.verify([], head: secondHash).ok)
        var stripped = [first, second]
        stripped[0].prevHash = nil; stripped[1].prevHash = nil
        XCTAssertFalse(ActivityChain.verify(stripped, head: secondHash).ok)
    }

    private func event(_ n: Int, at t: Int64) -> LocalData.ActivityEvent {
        LocalData.ActivityEvent(id: String(format: "00000000-0000-4000-8000-%012d", n), eventType: "item.fill", timestamp: t)
    }

    func testLocalDataAppendsChainedEventsAndPrunesToACheckpoint() throws {
        var data = LocalData()
        for n in 1...5 { data.appendChained(event(n, at: 1_000 + Int64(n))) }
        XCTAssertTrue(data.verifyEventsChain().ok)
        XCTAssertEqual(data.events.first?.prevHash, ActivityChain.genesis)
        XCTAssertEqual(data.eventsChain?.head, ActivityChain.hash(data.events[4].chainEvent))
        let dropped = data.events[1]
        data.trimEvents(now: 1_002 + LocalData.eventRetentionDays * 86_400 + 1)
        XCTAssertEqual(data.events.count, 3)
        XCTAssertEqual(data.eventsChain?.checkpoint, ActivityChain.hash(dropped.chainEvent))
        XCTAssertTrue(data.verifyEventsChain().ok)
        // Survives a save and a reload, and validation keeps the hashes.
        let decoded = try JSONDecoder().decode(LocalData.self, from: JSONEncoder().encode(data.validated()))
        XCTAssertTrue(decoded.verifyEventsChain().ok)
        var edited = decoded
        edited.events[1].count = 9
        XCTAssertFalse(edited.verifyEventsChain().ok)
        var cut = decoded
        cut.events.removeLast()
        XCTAssertFalse(cut.verifyEventsChain().ok)
    }

    func testOlderFilesWithoutAChainStillVerify() throws {
        let data = LocalData(events: [event(1, at: 1), event(2, at: 2)])
        XCTAssertNil(data.eventsChain)
        XCTAssertTrue(data.verifyEventsChain().ok)
    }
}
