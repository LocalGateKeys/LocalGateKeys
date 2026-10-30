import XCTest
@testable import LocalGateKeys

/// UX plan workstream 5: the vault search's `>` parser (Android `VaultCommandsTest`, Windows palette `>` prefix).
final class PhoneCommandsTests: XCTestCase {
    func test_plain_queries_search_items() {
        XCTAssertNil(PhoneCommand.matches(""))
        XCTAssertNil(PhoneCommand.matches("bank"))
        XCTAssertNil(PhoneCommand.matches("a>b"))
        XCTAssertNil(PhoneCommand.filter("mail"))
    }

    func test_a_lone_prefix_lists_every_action() {
        XCTAssertEqual(PhoneCommand.matches(">"), PhoneCommand.allCases)
        XCTAssertEqual(PhoneCommand.matches("  >  "), PhoneCommand.allCases)
        XCTAssertEqual(PhoneCommand.filter("> sync "), "sync")
    }

    func test_words_filter_by_title_and_keywords() {
        XCTAssertEqual(PhoneCommand.matches(">lock"), [.lockNow])
        XCTAssertEqual(PhoneCommand.matches("> GENERATE"), [.generatePassword])
        XCTAssertEqual(PhoneCommand.matches(">qr"), [.scanQR])
        XCTAssertEqual(PhoneCommand.matches(">sync now"), [.syncNow])
        XCTAssertEqual(PhoneCommand.matches(">deleted"), [.trash])
        XCTAssertEqual(PhoneCommand.matches(">security"), [.securityCheck])
        XCTAssertEqual(PhoneCommand.matches(">zzz"), [])
        XCTAssertTrue(PhoneCommand.matches(">settings")!.contains(.settings))
    }

    func test_the_plan_actions_are_listed() {
        let ids = Set(PhoneCommand.allCases.map(\.rawValue))
        XCTAssertTrue(ids.isSuperset(of: ["new-item", "generate-password", "scan-qr", "lock", "sync-now", "security-check",
                                          "trash", "settings", "sync-status", "show-setup"]))
    }
}
