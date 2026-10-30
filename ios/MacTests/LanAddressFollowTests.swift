import XCTest
import LGKCore
@testable import AppSharedMac

/// The Mac host following its own address (desktop `lan_interfaces.followed_endpoint`) and the Sync page wording.
final class LanAddressFollowTests: XCTestCase {
    let stored = try! LanEndpoint(validating: "192.168.1.20", port: 50_123)
    func a(_ address: String, _ interface: String = "en0") -> LanInterfaceAddress { LanInterfaceAddress(interface: interface, address: address) }

    func test_follows_the_one_new_address_keeping_the_port() {
        XCTAssertEqual(LanAddressPicker.followed(stored: stored, candidates: [a("192.168.1.23")]),
                       try LanEndpoint(validating: "192.168.1.23", port: 50_123))
        // A link-local address beside one private one: the private one.
        XCTAssertEqual(LanAddressPicker.followed(stored: stored, candidates: [a("10.0.0.5"), a("169.254.7.8", "en1")])?.host, "10.0.0.5")
        // Only a link-local address left: that one.
        XCTAssertEqual(LanAddressPicker.followed(stored: stored, candidates: [a("169.254.7.8")])?.host, "169.254.7.8")
    }

    func test_keeps_the_stored_address_otherwise() {
        XCTAssertNil(LanAddressPicker.followed(stored: stored, candidates: []), "nothing read: never move")
        XCTAssertNil(LanAddressPicker.followed(stored: stored, candidates: [a("192.168.1.20"), a("10.0.0.5", "en1")]), "still here")
        XCTAssertNil(LanAddressPicker.followed(stored: stored, candidates: [a("192.168.1.30"), a("10.0.0.5", "en1")]), "the user chooses")
        XCTAssertNil(LanAddressPicker.followed(stored: stored, candidates: [a("169.254.1.1"), a("169.254.2.2", "en1")]))
    }

    @MainActor func test_followed_wording() {
        XCTAssertEqual(SyncPageModel.followedText("192.168.1.23:47821"), "Now listening on 192.168.1.23:47821 (address changed).")
    }
}
