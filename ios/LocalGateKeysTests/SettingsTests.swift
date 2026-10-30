import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class SettingsTests: XCTestCase {
    func test_acknowledgements_ship_both_licences() throws {
        let list = Acknowledgement.all
        XCTAssertEqual(list.map(\.name), ["swift-crypto", "phc-winner-argon2"])
        let crypto = try XCTUnwrap(list.first)
        XCTAssertEqual(crypto.licence, "Apache-2.0")
        XCTAssertTrue(crypto.text.contains("Apache License"))
        XCTAssertTrue(crypto.text.contains("The SwiftCrypto Project"), "NOTICE included")
        XCTAssertEqual(list[1].licence, "CC0-1.0")
        XCTAssertTrue(list[1].text.contains("CC0 1.0"))
    }

    func test_import_card_text() {
        XCTAssertEqual(ImportCard.title, "Import your passwords")
        XCTAssertTrue(ImportCard.text.hasPrefix("Bring your logins over from another password manager or browser."))
        XCTAssertTrue(ImportCard.text.contains("Export Data to Another App"))
        XCTAssertTrue(ImportCard.text.contains("Bitwarden, 1Password, KeePass and others"))
    }

    func test_about_text() {
        XCTAssertEqual(SettingsView.dataNotCollected, "Your vault stays on your devices. When you buy Pro, the app sends the App Store receipt to our licence server so your other devices can be unlocked. The receipt has no name or email.")
        XCTAssertEqual(SettingsView.safariHelp, "To be offered saving in Safari, turn on LocalGateKeys in Settings › Apps › Safari › Extensions and allow it on all websites.")
    }

    func test_sync_status_text() {
        XCTAssertEqual(SettingsView.syncStatus(joined: false, lastSyncedAt: nil), "Not set up")
        XCTAssertEqual(SettingsView.syncStatus(joined: true, lastSyncedAt: nil), "On")
        XCTAssertTrue(SettingsView.syncStatus(joined: true, lastSyncedAt: 1_790_000_000).hasPrefix("Last synced "))
    }

    func test_extension_interface_style_follows_appearance() {
        // The extension's mapping lives in AutoFill; the app's in Appearance.colorScheme.
        XCTAssertNil(Appearance.system.colorScheme)
        XCTAssertEqual(Appearance.light.colorScheme, .light)
        XCTAssertEqual(Appearance.dark.colorScheme, .dark)
    }
}
