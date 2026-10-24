import XCTest
import UIKit
import UniformTypeIdentifiers
import AppShared
@testable import LocalGateKeys

/// A desktop-shaped passkey item (`PasskeyRecord.newPayload`), normalised. `usable` false: an RS256 import.
func passkeyItem(id: String = "9a550000-0000-4000-8000-000000000001", usable: Bool = true) throws -> JSONValue {
    let made = PasskeyRecord.newPayload(rpID: "example.com", rpName: "Example", userName: "ada", userDisplayName: "Ada",
                                        userHandle: [1, 2, 3], credentialID: [UInt8](repeating: 5, count: 16),
                                        key: PasskeyKey.generate(), today: "2026-10-18")
    guard case .object(var payload) = made.fields else { throw CocoaError(.coderInvalidValue) }
    if !usable { payload["algorithm"] = .string("RS256") }
    return try Normalise.normalForm(ns: .item, record: rec([
        "id": .string(id), "kind": .string("passkey"), "title": .string(made.title), "payload": .object(payload),
        "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_100), "favorite": .bool(false), "tags": .array([]),
    ]))
}

@MainActor
final class ItemDetailModelTests: XCTestCase {
    func item(_ r: JSONValue) -> VaultItem { VaultItem.items(from: snapshot([r]))[0] }

    func test_clipboard_is_local_only_and_expires_in_60s() {
        let pb = FakePasteboard(); let clock = TestClock(1_790_000_000)
        let settings = AppSettings(defaults: UserDefaults(suiteName: "clip-\(UUID().uuidString)")!)
        SecretClipboard(pasteboard: pb, clock: clock, settings: settings).copy("s3cret")
        XCTAssertEqual(pb.items.first?[UTType.utf8PlainText.identifier] as? String, "s3cret")
        XCTAssertEqual(pb.options[.localOnly] as? Bool, true)
        XCTAssertEqual(pb.options[.expirationDate] as? Date, Date(timeIntervalSince1970: 1_790_000_060))
    }

    func test_login_fields_hide_password_until_revealed_and_copy_it() {
        let pb = FakePasteboard()
        let m = ItemDetailModel(item: item(webLogin), clipboard: SecretClipboard(pasteboard: pb, clock: TestClock(0)), clock: TestClock(0))
        let pw = m.fields.first { $0.label == "Password" }!
        XCTAssertTrue(pw.isSecret)
        XCTAssertEqual(m.displayValue(pw), "••••••••")
        m.toggleReveal(pw); XCTAssertEqual(m.displayValue(pw), "Maple-Orbit-7731")
        m.copy(pw); XCTAssertEqual(pb.items.first?[UTType.utf8PlainText.identifier] as? String, "Maple-Orbit-7731")
        XCTAssertEqual(m.fields.first { $0.label == "Username" }?.isSecret, false)
    }

    func test_conceal_off_shows_protected_fields_at_once() {
        let m = ItemDetailModel(item: item(webLogin), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)),
                                clock: TestClock(0), concealSecrets: false)
        let pw = m.fields.first { $0.label == "Password" }!
        XCTAssertEqual(m.displayValue(pw), "Maple-Orbit-7731")
        m.toggleReveal(pw); XCTAssertEqual(m.displayValue(pw), ItemDetailModel.mask, "the eye still hides it")
    }

    /// Audit 2026-10-24 L-8: while the screen is recorded or mirrored, reveals are dropped and refused.
    func test_screen_capture_masks_and_refuses_reveals() {
        let m = ItemDetailModel(item: item(webLogin), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)),
                                clock: TestClock(0), concealSecrets: false)
        let pw = m.fields.first { $0.label == "Password" }!
        XCTAssertEqual(m.displayValue(pw), "Maple-Orbit-7731")
        m.screenCaptured = true
        XCTAssertEqual(m.displayValue(pw), ItemDetailModel.mask)
        m.toggleReveal(pw)
        XCTAssertEqual(m.displayValue(pw), ItemDetailModel.mask, "no reveal while captured")
        m.screenCaptured = false
        XCTAssertEqual(m.displayValue(pw), ItemDetailModel.mask, "nothing comes back on its own")
        m.toggleReveal(pw); XCTAssertEqual(m.displayValue(pw), "Maple-Orbit-7731")
    }

    func test_screen_capture_monitor_follows_the_notification() {
        let center = NotificationCenter()
        var captured = false
        let monitor = ScreenCaptureMonitor(center: center, read: { captured })
        XCTAssertFalse(monitor.isCaptured)
        captured = true
        center.post(name: UIScreen.capturedDidChangeNotification, object: nil)
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))   // the observer runs on the main queue
        XCTAssertTrue(monitor.isCaptured)
        captured = false
        monitor.refresh()
        XCTAssertFalse(monitor.isCaptured)
    }

    /// Audit 2026-10-24 L-8: third-party keyboards are refused.
    func test_custom_keyboards_are_refused() {
        XCTAssertFalse(AppDelegate.allows(.keyboard))
        XCTAssertFalse(AppDelegate().application(UIApplication.shared, shouldAllowExtensionPointIdentifier: .keyboard))
    }

    func test_card_protected_fields_are_masked() {
        let m = ItemDetailModel(item: item(card), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)), clock: TestClock(0))
        XCTAssertEqual(m.fields.first { $0.label == "Card number" }?.isSecret, true)
        XCTAssertEqual(m.fields.first { $0.label == "CVV" }?.isSecret, true)
    }

    func test_totp_uses_lgkcore_and_ring_reflects_remaining_period() throws {
        let clock = TestClock(1_790_000_500)   // 1790000500 % 30 == 10
        let m = ItemDetailModel(item: item(webLogin), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: clock), clock: clock)
        let t = try XCTUnwrap(m.totp)
        XCTAssertEqual(t.code, try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, at: 1_790_000_500))
        XCTAssertEqual(t.secondsRemaining, 20)
        XCTAssertEqual(t.fractionRemaining, 20.0 / 30.0, accuracy: 1e-9)
        clock.now += 20; m.tick()
        XCTAssertEqual(m.totp?.secondsRemaining, 30)
        XCTAssertNotEqual(m.totp?.code, t.code)
    }

    func test_code_tile_rebuilds_its_model_when_the_totp_secret_changes() throws {
        let clock = TestClock(1_790_000_500); let pb = FakePasteboard()
        let clip = SecretClipboard(pasteboard: pb, clock: clock)
        let before = item(webLogin)
        let m1 = CodeTile.model(for: before, current: nil, clipboard: clip, clock: clock)
        XCTAssertTrue(CodeTile.model(for: before, current: m1, clipboard: clip, clock: clock) === m1, "same item keeps its model")
        guard case .object(var r) = webLogin, case .object(var t)? = r["totp"] else { return XCTFail() }
        t["secret"] = .string("GEZDGNBVGY3TQOJQ"); r["totp"] = .object(t)
        let after = item(.object(r))
        let m2 = CodeTile.model(for: after, current: m1, clipboard: clip, clock: clock)
        XCTAssertFalse(m2 === m1)
        let fresh = try TOTP.code(secret: "GEZDGNBVGY3TQOJQ", algorithm: "SHA1", digits: 6, period: 30, at: 1_790_000_500)
        XCTAssertEqual(m2.totp?.code, fresh)
        XCTAssertNotEqual(m1.totp?.code, fresh)
        m2.copyTOTP()
        XCTAssertEqual(pb.items.first?[UTType.utf8PlainText.identifier] as? String, fresh)
    }

    func test_no_totp_for_items_without_one() {
        let m = ItemDetailModel(item: item(note), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)), clock: TestClock(0))
        XCTAssertNil(m.totp)
    }

    func test_invalid_totp_secret_gives_no_code() {
        let bad = rec(["id": .string("w9"), "kind": .string("web"), "label": .string("x"), "username": .string(""),
                       "password": .string(""), "scope": rec(["origin": .string("https://x.example")]),
                       "totp": rec(["secret": .string("!!!not base32!!!")])])
        let m = ItemDetailModel(item: item(bad), clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)), clock: TestClock(0))
        XCTAssertNil(m.totp)
    }

    func test_copy_totp_is_local_only_with_60s_expiry() throws {
        let pb = FakePasteboard(); let clock = TestClock(1_790_000_500)
        let m = ItemDetailModel(item: item(webLogin), clipboard: SecretClipboard(pasteboard: pb, clock: clock), clock: clock)
        m.copyTOTP()
        XCTAssertEqual(pb.items.first?[UTType.utf8PlainText.identifier] as? String, m.totp?.code)
        XCTAssertEqual(pb.options[.localOnly] as? Bool, true)
        XCTAssertEqual(pb.options[.expirationDate] as? Date, Date(timeIntervalSince1970: 1_790_000_560))
    }

    func test_passkey_detail_hides_private_key() throws {
        let record = try passkeyItem()
        guard case .object(let r) = record, case .string(let key)? = r["payload"]?.objectValue?["private_key"] else { return XCTFail() }
        let pb = FakePasteboard()
        let m = ItemDetailModel(item: item(record), clipboard: SecretClipboard(pasteboard: pb, clock: TestClock(0)),
                                clock: TestClock(0), concealSecrets: false)
        XCTAssertEqual(m.fields.map(\.label), ["Website", "User", "Created", "Status"])
        XCTAssertEqual(m.fields.map(\.value), ["example.com", "ada", "2026-10-18", "Can sign in"])
        for f in m.fields {
            XCTAssertFalse(f.value.contains(key)); XCTAssertFalse(m.displayValue(f).contains(key))
            m.toggleReveal(f); XCTAssertFalse(m.displayValue(f).contains(key))
            m.copy(f)
        }
        let copied = pb.history.compactMap { $0.first?[UTType.utf8PlainText.identifier] as? String }
        XCTAssertEqual(copied.count, m.fields.count)
        XCTAssertFalse(copied.contains { $0.contains(key) }, "the private key never reaches the pasteboard")
        XCTAssertFalse(m.fields.contains { $0.id == "private_key" || $0.id == "credential_id" || $0.id == "user_handle" })
        let backup = ItemDetailModel(item: item(try passkeyItem(usable: false)),
                                     clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)), clock: TestClock(0))
        XCTAssertEqual(backup.fields.last?.value, "Backup only")
    }
}
