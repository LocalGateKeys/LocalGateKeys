import XCTest
@testable import AppShared

final class AuroraTests: XCTestCase {
    func test_reduce_transparency_is_plain_background() {
        XCTAssertNil(AuroraStyle.blobOpacity(dark: false, reduceTransparency: true, increasedContrast: false))
        XCTAssertNil(AuroraStyle.blobOpacity(dark: true, reduceTransparency: true, increasedContrast: true))
    }

    func test_opacity_light_dark_and_contrast() {
        XCTAssertEqual(AuroraStyle.blobOpacity(dark: false, reduceTransparency: false, increasedContrast: false), 0.35)
        XCTAssertEqual(AuroraStyle.blobOpacity(dark: true, reduceTransparency: false, increasedContrast: false), 0.45)
        XCTAssertEqual(AuroraStyle.blobOpacity(dark: false, reduceTransparency: false, increasedContrast: true), 0.175)
        XCTAssertEqual(AuroraStyle.blobOpacity(dark: true, reduceTransparency: false, increasedContrast: true), 0.225)
    }

    func test_avatar_initials() {
        XCTAssertNil(AvatarInitials.from(""))
        XCTAssertNil(AvatarInitials.from("  "))
        XCTAssertNil(AvatarInitials.from("12"))
        XCTAssertEqual(AvatarInitials.from("ip"), "IP")
        XCTAssertEqual(AvatarInitials.from(" i p "), "IP")
        XCTAssertEqual(AvatarInitials.from("Alex Morgan"), "AM")
        XCTAssertEqual(AvatarInitials.from("abc"), "AB")
        XCTAssertEqual(AvatarInitials.from("é"), "É")
    }

    func test_initials_setting_round_trips_and_is_capped() {
        let d = UserDefaults(suiteName: "aurora-\(UUID().uuidString)")!
        let s = AppSettings(defaults: d)
        XCTAssertEqual(s.initials, "")
        s.initials = "alex"
        XCTAssertEqual(AppSettings(defaults: d).initials, "AL")
    }
}
