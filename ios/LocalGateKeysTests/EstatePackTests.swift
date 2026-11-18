import XCTest
#if os(iOS)
@testable import LocalGateKeys
#endif

/// The estate pack note (sub-plan 12, Windows `tests/test_estate_pack.py`): one "## <label>" heading per field in
/// template order, the shard holders listed by nickname only under their heading.
@MainActor
final class EstatePackTests: XCTestCase {
    func testOneHeadingPerField() {
        let body = EstatePack.body()
        let headings = body.split(separator: "\n").filter { $0.hasPrefix("## ") }.map { String($0.dropFirst(3)) }
        XCTAssertEqual(headings, EstatePack.fields.map(\.label))
        XCTAssertEqual(EstatePack.fields.map(\.name),
                       ["will_location", "executor", "accounts_to_close", "devices_unlock", "shard_holders"])
        XCTAssertFalse(body.contains("- "))
    }

    func testShardHoldersByNickname() {
        let body = EstatePack.body(holders: ["  Anna ", "", "Ben"])
        let tail = body.components(separatedBy: "## \(EstatePack.fields[4].label)\n").last ?? ""
        XCTAssertEqual(tail, "- Anna\n- Ben\n")
        // Holders appear only under their own heading.
        let head = body.components(separatedBy: "## \(EstatePack.fields[4].label)\n").first ?? ""
        XCTAssertFalse(head.contains("Anna"))
    }
}
