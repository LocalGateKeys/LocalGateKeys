import XCTest
import UIKit
import AppShared
@testable import LocalGateKeys

@MainActor
final class EditorTOTPAndInputTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    /// A Pro phone: adding or changing 2FA codes is a Pro feature (free-plan behaviour is tested below).
    func editor(_ store: MemoryStore, item: VaultItem? = nil, isPro: Bool = true) -> EditorModel {
        EditorModel(store: store, pro: ProModel(purchases: FakePurchases(), licenseKeys: [:], purchased: isPro), editing: item, kind: .web,
                    clock: clock, random: CountingRandom(), background: FakeBackgroundTasks())
    }

    func storedRecord(_ store: MemoryStore) throws -> [String: JSONValue] {
        guard case .object(let w)? = store.snapshot.records.values.first, case .object(let r)? = w["record"] else {
            throw XCTSkip("unreachable")
        }
        return r
    }

    // MARK: 2FA secret

    // MARK: 2FA on the free plan (Pro-only feature; existing codes are never locked)

    func test_free_plan_refuses_a_new_secret_and_writes_nothing() throws {
        let store = MemoryStore()
        let e = editor(store, isPro: false)
        XCTAssertTrue(e.totpNeedsPro)
        e.set("label", "Shop"); e.set("origin", "https://shop.example"); e.set("totp", "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(e.save(), .needsPro)
        XCTAssertTrue(e.showUpgrade)
        XCTAssertEqual(e.totpError, ProFeatures.totpMessage)
        XCTAssertEqual(store.commits, 0)
        e.set("totp", "")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
    }

    func test_free_plan_keeps_an_existing_secret_through_other_edits_and_can_clear_it() throws {
        let store = MemoryStore(snapshot([webLogin]))
        let item = VaultItem.items(from: store.snapshot)[0]
        let e = editor(store, item: item, isPro: false)
        let saved = try storedRecord(store)["totp"]
        e.set("label", "Renamed")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        XCTAssertEqual(try storedRecord(store)["totp"], saved)
        let change = editor(store, item: VaultItem.items(from: store.snapshot)[0], isPro: false)
        change.set("totp", "KRSXG5CTMVRXEZLU")
        XCTAssertEqual(change.save(), .needsPro)
        XCTAssertEqual(try storedRecord(store)["totp"], saved)
        let clear = editor(store, item: VaultItem.items(from: store.snapshot)[0], isPro: false)
        clear.set("totp", "")
        XCTAssertEqual(clear.save(), .saved, clear.error ?? "")
        XCTAssertNil(try storedRecord(store)["totp"])
    }

    func test_pro_features_rule() {
        let code = JSONValue.object(["secret": .string("JBSWY3DPEHPK3PXP")])
        let other = JSONValue.object(["secret": .string("KRSXG5CTMVRXEZLU")])
        XCTAssertTrue(ProFeatures.totpChangeNeedsPro(new: code, old: nil))
        XCTAssertTrue(ProFeatures.totpChangeNeedsPro(new: other, old: code))
        XCTAssertFalse(ProFeatures.totpChangeNeedsPro(new: code, old: code))
        XCTAssertFalse(ProFeatures.totpChangeNeedsPro(new: nil, old: code))
        XCTAssertFalse(ProFeatures.totpChangeNeedsPro(new: .null, old: code))
    }

    func test_new_login_with_base32_secret_stores_the_desktop_shape() throws {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "Shop"); e.set("username", "me"); e.set("password", "pw"); e.set("origin", "https://shop.example")
        e.set("totp", "jbsw y3dp-ehpk 3pxp")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        let r = try storedRecord(store)
        XCTAssertEqual(r["totp"], .object(["secret": .string("JBSWY3DPEHPK3PXP"), "algorithm": .string("SHA1"),
                                           "digits": .int(6), "period": .int(30)]))
        // The record passes the desktop's validation rules (LGKCore Normalise mirrors item_schema) unchanged.
        let again = try Normalise.normalForm(ns: .entry, record: .object(r))
        XCTAssertTrue(EditorModel.same(again, .object(r)))
        // And the detail screen can now produce a code.
        XCTAssertNotNil(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, at: clock.now))
    }

    func test_otpauth_uri_is_parsed_into_its_parameters() throws {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        e.set("totp", "otpauth://totp/Shop:me?secret=JBSWY3DPEHPK3PXP&issuer=Shop&algorithm=SHA256&digits=8&period=60")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        let r = try storedRecord(store)
        XCTAssertEqual(r["totp"], .object(["secret": .string("JBSWY3DPEHPK3PXP"), "algorithm": .string("SHA256"),
                                           "digits": .int(8), "period": .int(60)]))
        XCTAssertNoThrow(try Normalise.normalForm(ns: .entry, record: .object(r)))
    }

    func test_existing_secret_is_shown_and_unchanged_save_writes_nothing() throws {
        let store = MemoryStore(snapshot([webLogin]))
        let e = editor(store, item: VaultItem.items(from: store.snapshot)[0])
        XCTAssertEqual(e.value("totp"), "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(e.save(), .unchanged)
        XCTAssertEqual(store.commits, 0)
    }

    func test_clearing_the_field_removes_the_totp() throws {
        let store = MemoryStore(snapshot([webLogin]))
        let e = editor(store, item: VaultItem.items(from: store.snapshot)[0])
        e.set("totp", "")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        XCTAssertNil(try storedRecord(store)["totp"])
    }

    func test_invalid_secret_is_rejected_with_an_inline_error() throws {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        for bad in ["not base32!", "JBSW", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9"] {
            e.set("totp", bad)
            XCTAssertEqual(e.save(), .invalid, bad)
            XCTAssertNotNil(e.totpError, bad)
        }
        XCTAssertEqual(store.commits, 0)
        e.set("totp", "JBSWY3DPEHPK3PXP")
        XCTAssertNil(e.totpError, "editing the field clears its error")
    }

    func test_scanned_otpauth_qr_fills_the_field() throws {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        e.scanTOTP("otpauth://totp/Shop:me?secret=JBSWY3DPEHPK3PXP&issuer=Shop&digits=8\n")
        XCTAssertNil(e.totpError)
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        XCTAssertEqual(try storedRecord(store)["totp"]?.objectValue?["digits"], .int(8))
    }

    func test_scanned_qr_that_is_not_a_setup_code_keeps_the_field() {
        let e = editor(MemoryStore())
        e.set("totp", "JBSWY3DPEHPK3PXP")
        for (code, message) in [("https://shop.example/login", EditorModel.notTOTPQRMessage),
                                ("", EditorModel.notTOTPQRMessage),
                                ("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8", EditorModel.migrationQRMessage),
                                ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", TOTP.message(for: .notOtpauthURI))] {
            e.scanTOTP(code)
            XCTAssertEqual(e.totpError, message, code)
            XCTAssertEqual(e.value("totp"), "JBSWY3DPEHPK3PXP", code)
        }
    }

    func test_totp_field_is_masked() {
        XCTAssertEqual(EditorKind.web.fields.first { $0.key == "totp" }?.secret, true)
    }

    // MARK: Apple Passwords save prompt

    /// No field the vault configures may look like a login form to iOS.
    func test_no_editor_field_uses_a_credential_content_type() {
        for kind in EditorKind.allCases {
            for field in kind.fields {
                if let t = VaultInputTraits.contentType(for: field) {
                    XCTAssertFalse(VaultInputTraits.forbidden.contains(t), "\(kind).\(field.key)")
                }
                if field.secret { XCTAssertEqual(VaultInputTraits.contentType(for: field), .oneTimeCode, "\(kind).\(field.key)") }
            }
        }
        XCTAssertFalse(VaultInputTraits.forbidden.contains(VaultInputTraits.secretContentType))
    }

    // MARK: StoreKit at launch

    func test_launch_refresh_reads_only_the_entitlement() async {
        let purchases = FakePurchases()
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        p.startObserving()
        await p.refresh()
        XCTAssertEqual(purchases.priceCalls, 0, "no Product.products at launch")
        XCTAssertEqual(purchases.restoreCalls, 0, "no AppStore.sync at launch")
        XCTAssertNil(p.price)
        await p.loadPrice()
        XCTAssertEqual(p.price, "$4.99")
    }
}
