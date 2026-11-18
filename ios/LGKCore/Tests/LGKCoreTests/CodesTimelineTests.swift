import XCTest
@testable import LGKCore

/// Sub-plan 06: the widgets' timeline (Review Focus 2 and 3: no stale code, refresh at each period boundary).
final class CodesTimelineTests: XCTestCase {
    /// RFC 6238 SHA1 seed "12345678901234567890" in Base32.
    let rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    /// 2026-01-01T00:00:10Z.
    let now = Date(timeIntervalSince1970: 1_767_225_610)
    var suites: [String] = []

    override func tearDown() {
        for s in suites { UserDefaults().removePersistentDomain(forName: s) }
        suites = []
        super.tearDown()
    }

    func store(pins: [String], codes: [WatchCode]) -> (PinnedCodeStore, MemoryKeychain) {
        let name = "timeline-\(UUID().uuidString)"
        suites.append(name)
        let keychain = MemoryKeychain()
        let s = PinnedCodeStore(defaults: UserDefaults(suiteName: name)!, keychain: keychain)
        s.pinnedIDs = pins
        s.replace(codes)
        return (s, keychain)
    }

    func code(_ id: String, period: Int = 30) -> WatchCode {
        WatchCode(id: id, title: id.uppercased(), secret: rfcSecret, period: period)
    }

    func at(_ seconds: Int64) -> Date { Date(timeIntervalSince1970: TimeInterval(seconds)) }

    func test_entries_start_now_and_change_at_each_period_boundary() {
        let entries = CodesTimeline.entries(from: [code("a")], now: now, count: 3)
        XCTAssertEqual(entries.map { $0.date }, [now, at(1_767_225_630), at(1_767_225_660)])
        XCTAssertEqual(entries[0].codes.map { $0.code }, ["745690"])
        XCTAssertEqual(entries[1].codes.map { $0.code }, ["119644"])
        XCTAssertNotEqual(entries[0].codes[0].code, entries[1].codes[0].code)
        XCTAssertEqual(entries[0].codes.map { $0.title }, ["A"])
    }

    func test_each_entry_holds_until_the_next_one_with_mixed_periods() {
        let codes = [code("a"), code("b", period: 60)]
        let entries = CodesTimeline.entries(from: codes, now: now, count: 6)
        XCTAssertEqual(entries.count, 6)
        for (i, e) in entries.enumerated().dropLast() {
            let from = Int64(e.date.timeIntervalSince1970.rounded(.down))
            let until = Int64(entries[i + 1].date.timeIntervalSince1970)
            XCTAssertGreaterThan(until, from)
            // Never an expired code: every second up to the next entry gives the same digits.
            for t in [from, until - 1] {
                XCTAssertEqual(e.codes.map { $0.code }, codes.compactMap { $0.current(at: t)?.code })
            }
        }
    }

    func test_invalid_codes_are_left_out_and_no_code_gives_one_empty_entry() {
        let bad = WatchCode(id: "x", title: "X", secret: "not base32!")
        XCTAssertEqual(CodesTimeline.entries(from: [bad, code("a")], now: now, count: 2).map { $0.codes.count }, [1, 1])
        let none = CodesTimeline.entries(from: [bad], now: now, count: 5)
        XCTAssertEqual(none.count, 1)
        XCTAssertTrue(none[0].codes.isEmpty)
        XCTAssertTrue(CodesTimeline.entries(from: [code("a")], now: now, count: 0).isEmpty)
        XCTAssertTrue(CodesTimeline.entries(from: [code("a")], now: Date(timeIntervalSince1970: -1), count: 2).isEmpty)
    }

    func test_widget_shows_codes_then_a_codeless_entry_where_the_last_code_ends() {
        let (s, _) = store(pins: ["a", "b"], codes: [code("a"), code("b")])
        let entries = CodesTimeline.widgetEntries(store: s, now: now, count: 3, phoneLocked: { XCTFail(); return false })
        XCTAssertEqual(entries.map(\.date), [now, at(1_767_225_630), at(1_767_225_660), at(1_767_225_690)])
        XCTAssertEqual(entries[0].content, .codes([.init(title: "A", code: "745690"), .init(title: "B", code: "745690")]))
        XCTAssertEqual(entries.last?.content, .openApp, "a late reload never leaves an expired code on screen")
    }

    func test_widget_timeline_ends_at_the_expiry() {
        let (s, _) = store(pins: ["a"], codes: [code("a")])
        s.expiresAt = at(1_767_225_645)
        let entries = CodesTimeline.widgetEntries(store: s, now: now, count: 20, phoneLocked: { false })
        XCTAssertEqual(entries.map(\.date), [now, at(1_767_225_630), at(1_767_225_645)])
        XCTAssertEqual(entries.last?.content, .openApp)
        let after = CodesTimeline.widgetEntries(store: s, now: at(1_767_225_645), phoneLocked: { true })
        XCTAssertEqual(after.map(\.content), [.openApp], "past the expiry: open the app, even with the phone locked")
    }

    func test_widget_states_without_a_code() {
        let (empty, _) = store(pins: [], codes: [])
        XCTAssertEqual(CodesTimeline.widgetEntries(store: empty, now: now, phoneLocked: { true }).map(\.content), [.empty])

        let (locked, keychain) = store(pins: ["a"], codes: [code("a")])
        keychain.delete(key: PinnedCodeStore.secretsKey)   // as the Keychain answers while the iPhone is locked
        XCTAssertEqual(CodesTimeline.widgetEntries(store: locked, now: now, phoneLocked: { true }).map(\.content), [.phoneLocked])
        XCTAssertEqual(CodesTimeline.widgetEntries(store: locked, now: now, phoneLocked: { false }).map(\.content), [.openApp],
                       "forgotten on lock: open the app")
    }

    func test_unpinning_the_last_code_shows_the_empty_state_not_a_stale_code() {
        let (s, keychain) = store(pins: ["a"], codes: [code("a")])
        s.pinnedIDs = []   // the secret is still there: only the pin list changed so far
        XCTAssertFalse(keychain.isEmpty)
        XCTAssertEqual(CodesTimeline.widgetEntries(store: s, now: now, phoneLocked: { false }).map(\.content), [.empty])
    }

    func test_widget_shows_at_most_four_codes() {
        let ids = ["a", "b", "c", "d", "e", "f"]
        let (s, _) = store(pins: ids, codes: ids.map { code($0) })
        let entries = CodesTimeline.widgetEntries(store: s, now: now, phoneLocked: { false })
        XCTAssertEqual(entries.count, CodesTimeline.widgetEntryCount + 1)
        guard case .codes(let shown) = entries[0].content else { return XCTFail() }
        XCTAssertEqual(shown.map(\.title), ["A", "B", "C", "D"])
    }

    /// The Apple Watch complication (task 4): each span ends at the next period boundary, where the next one starts,
    /// and its ring starts at the beginning of the period (mid-period at `now`).
    func test_watch_spans_end_at_each_period_boundary() {
        let spans = CodesTimeline.spans(of: code("a"), now: now, count: 2)
        XCTAssertEqual(spans, [
            CodeSpan(date: now, periodStart: at(1_767_225_600), end: at(1_767_225_630), title: "A", code: "745690"),
            CodeSpan(date: at(1_767_225_630), periodStart: at(1_767_225_630), end: at(1_767_225_660), title: "A",
                     code: "119644"),
        ])
        XCTAssertTrue(CodesTimeline.spans(of: code("a"), now: now, count: 0).isEmpty)
        XCTAssertTrue(CodesTimeline.spans(of: code("a", period: 0), now: now, count: 3).isEmpty)
        XCTAssertTrue(CodesTimeline.spans(of: WatchCode(id: "x", title: "X", secret: "not base32!"), now: now,
                                          count: 3).isEmpty)
        XCTAssertTrue(CodesTimeline.spans(of: code("a"), now: Date(timeIntervalSince1970: .nan), count: 3).isEmpty)
    }

    func test_open_url() {
        XCTAssertTrue(CodesTimeline.isOpenURL(CodesTimeline.openURL))
        XCTAssertFalse(CodesTimeline.isOpenURL(URL(string: "localgatekeys://vault")!))
        XCTAssertFalse(CodesTimeline.isOpenURL(URL(fileURLWithPath: "/tmp/codes.lgkshare")))
    }
}
