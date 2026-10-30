import XCTest
@testable import LGKCore

final class PeerAddressRefreshTests: XCTestCase {
    func qr() throws -> String { String(decoding: try Vectors.data("lan/qr_payload.txt"), as: UTF8.self) }

    func testMatchingQRMovesOnlyTheAddress() throws {
        let offer = try PairingOffer.parseQR(try qr().trimmingCharacters(in: .whitespacesAndNewlines))
        let old = try LanEndpoint(validating: "192.168.1.99", port: 48201)
        let pinned = PinnedPeer(deviceID: offer.inviterDeviceID, groupID: offer.groupID,
                                signingPublic: offer.inviterSigningPublic, exchangePublic: offer.inviterExchangePublic,
                                endpoint: old)
        let moved = try PeerAddressRefresh.refreshed(pinned, qrText: try qr())
        XCTAssertEqual(moved.endpoint, offer.endpoint)
        XCTAssertEqual(moved.deviceID, pinned.deviceID)
        XCTAssertEqual(moved.signingPublic, pinned.signingPublic)
        XCTAssertEqual(moved.exchangePublic, pinned.exchangePublic)
    }

    func testOtherDevicesQRIsRefused() throws {
        let offer = try PairingOffer.parseQR(try qr().trimmingCharacters(in: .whitespacesAndNewlines))
        var key = offer.inviterSigningPublic
        key[0] ^= 1
        let pinned = PinnedPeer(deviceID: offer.inviterDeviceID, groupID: offer.groupID, signingPublic: key,
                                exchangePublic: offer.inviterExchangePublic, endpoint: nil)
        XCTAssertThrowsError(try PeerAddressRefresh.refreshed(pinned, qrText: try qr())) {
            XCTAssertEqual($0 as? PeerAddressRefresh.Refusal, .otherDevice)
        }
        var exchange = offer.inviterExchangePublic
        exchange[0] ^= 1
        let pinned2 = PinnedPeer(deviceID: offer.inviterDeviceID, groupID: offer.groupID,
                                 signingPublic: offer.inviterSigningPublic, exchangePublic: exchange, endpoint: nil)
        XCTAssertThrowsError(try PeerAddressRefresh.refreshed(pinned2, qrText: try qr())) {
            XCTAssertEqual($0 as? PeerAddressRefresh.Refusal, .otherDevice)
        }
        let pinned3 = PinnedPeer(deviceID: "someone-else", groupID: offer.groupID,
                                 signingPublic: offer.inviterSigningPublic, exchangePublic: offer.inviterExchangePublic,
                                 endpoint: nil)
        XCTAssertThrowsError(try PeerAddressRefresh.refreshed(pinned3, qrText: try qr()))
    }

    func testJunkIsNotAPairingCode() throws {
        let pinned = PinnedPeer(deviceID: "d", groupID: "g", signingPublic: [1], exchangePublic: [2], endpoint: nil)
        XCTAssertThrowsError(try PeerAddressRefresh.refreshed(pinned, qrText: "hello")) {
            XCTAssertEqual($0 as? PeerAddressRefresh.Refusal, .notAPairingCode)
        }
    }
}
