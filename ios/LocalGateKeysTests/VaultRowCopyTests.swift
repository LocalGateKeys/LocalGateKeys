import XCTest
import AppShared
@testable import LocalGateKeys

/// UX refresh §4: the Vault row's copy-password button and the long-press menu copy the same value.
@MainActor
final class VaultRowCopyTests: XCTestCase {
    func item(_ kind: String, password: String? = nil, payload: [String: JSONValue] = [:]) -> VaultItem? {
        var r: [String: JSONValue] = ["kind": .string(kind), "title": .string("Example"), "payload": .object(payload)]
        if let password { r["password"] = .string(password) }
        return VaultItem(id: "x", record: r)
    }

    func test_login_password_is_copyable() throws {
        XCTAssertEqual(try XCTUnwrap(item("web", password: "s3cret")).copyablePassword, "s3cret")
    }

    func test_empty_or_missing_password_is_not_copyable() throws {
        XCTAssertNil(try XCTUnwrap(item("web", password: "")).copyablePassword)
        XCTAssertNil(try XCTUnwrap(item("web")).copyablePassword)
        XCTAssertNil(try XCTUnwrap(item("note")).copyablePassword)
    }

    func test_wifi_password_comes_from_the_payload() throws {
        XCTAssertEqual(try XCTUnwrap(item("wifi", payload: ["password": .string("wpa-pass")])).copyablePassword, "wpa-pass")
    }
}
