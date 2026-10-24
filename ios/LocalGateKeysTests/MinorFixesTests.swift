import XCTest
import AppShared
@testable import LocalGateKeys

/// Task B6: the smaller device fixes.
@MainActor
final class MinorFixesTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    // MARK: delete of an item already gone

    func test_deleting_an_already_removed_item_says_so() {
        let store = MemoryStore(snapshot([note]))
        let item = VaultItem.items(from: store.snapshot)[0]
        let e = EditorModel(store: store, pro: ProModel(purchases: FakePurchases(), licenseKeys: [:]), editing: item,
                            kind: .note, clock: clock, random: CountingRandom(), background: FakeBackgroundTasks())
        store.snapshot = StoreSnapshot(records: [:], meta: [:], sync: nil, revision: store.snapshot.revision + 1)  // a sync removed it
        XCTAssertEqual(e.delete(), .unchanged)
        XCTAssertTrue(e.alreadyRemoved)
        XCTAssertEqual(EditorModel.alreadyRemovedMessage, "This item was already removed")
        XCTAssertNil(e.error, "not an error: the view closes after saying so")
        e.clearAlreadyRemoved()   // the alert's binding, when dismissed
        XCTAssertFalse(e.alreadyRemoved)
    }

    func test_deleting_an_already_removed_passkey_says_so() throws {
        let store = MemoryStore(snapshot([try passkeyItem()]))
        let m = PasskeyRenameModel(store: store, item: VaultItem.items(from: store.snapshot)[0], clock: clock,
                                   background: FakeBackgroundTasks())
        store.snapshot = StoreSnapshot()
        XCTAssertEqual(m.delete(), .unchanged)
        XCTAssertTrue(m.alreadyRemoved)
    }

    // MARK: desktop-only kinds can be deleted

    func sshKey(_ id: String = "55500000-0000-4000-8000-000000000001") -> JSONValue {
        rec(["id": .string(id), "kind": .string("ssh_key"), "title": .string("Server key"),
             "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_100), "favorite": .bool(false), "tags": .array([]),
             "payload": rec(["private_key": .string("-----BEGIN OPENSSH PRIVATE KEY-----"), "fields": .array([]),
                             "template_id": .null])])
    }

    func test_desktop_only_kinds_offer_delete_only() throws {
        for kind in ["desktop", "document"] {
            XCTAssertTrue(ItemDetailModel.offersDeleteOnly(kind: kind), kind)
        }
        for kind in ["web", "note", "card", "identity", "passkey", "ssh_key", "wifi", "bank_account", "api_key", "license",
                     "bookmark", "purchase", "warranty", "subscription"] {
            XCTAssertFalse(ItemDetailModel.offersDeleteOnly(kind: kind), kind)
        }
    }

    func test_desktop_only_item_delete_writes_a_tombstone() throws {
        let key = sshKey()
        let id = "55500000-0000-4000-8000-000000000001"
        var snap = snapshot([key])
        let identity = try DeviceIdentity.generate(deviceID: "phone-1", random: SystemRandomSource())
        snap.sync = SyncGroupState(groupID: "g", epoch: 1, key: Array(repeating: 1, count: 32), identity: identity,
                                   installID: "i", hasFolder: false, lastSeen: [:], peerDigests: [:], membersEpoch: 1,
                                   members: ["phone-1"], keyring: [], ownCounter: 0)
        snap.meta[id] = try SyncMeta.live(try XCTUnwrap(snap.records[id]), vv: ["desk": 3])
        let store = MemoryStore(snap)
        XCTAssertEqual(EditorModel.delete(id: id, store: store, clock: clock, background: FakeBackgroundTasks()), .saved)
        XCTAssertNil(store.snapshot.records[id])
        let tomb = try XCTUnwrap(store.snapshot.meta[id])
        XCTAssertTrue(tomb.deleted)
        XCTAssertEqual(tomb.vv["phone-1"], 1)
    }

    // MARK: AutoFill status in Settings

    func test_autofill_status_is_rechecked_and_open_errors_are_shown() async {
        var enabled = false
        var openError: (any Error)? = CocoaError(.featureUnsupported)
        let m = AutoFillStatusModel(isEnabled: { enabled }, openSettings: { if let e = openError { throw e } })
        XCTAssertNil(m.enabled)
        await m.refresh()
        XCTAssertEqual(m.enabled, false)
        await m.openSettings()
        XCTAssertEqual(m.openError, AutoFillStatusModel.openFailedMessage)
        // Back from the Settings app (scene .active): checked again, and the error goes.
        enabled = true; openError = nil
        await m.refresh()
        XCTAssertEqual(m.enabled, true)
        XCTAssertNil(m.openError)
        await m.openSettings()
        XCTAssertNil(m.openError)
    }

    // MARK: initials

    func test_initials_are_normalised_on_submit_not_while_typing() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "initials-\(UUID().uuidString)")!)
        var field = InitialsField(settings: settings)
        XCTAssertEqual(field.text, "")
        for prefix in ["J", "Jo", "John", "John ", "John D", "John Doe"] {
            field.text = prefix
            XCTAssertEqual(field.text, prefix, "typing is never rewritten")
        }
        XCTAssertEqual(settings.initials, "", "nothing stored until submit")
        field.submit()
        XCTAssertEqual(settings.initials, "JD")
        XCTAssertEqual(field.text, "JD")
        field.text = "  "; field.submit()
        XCTAssertEqual(settings.initials, "")
        XCTAssertEqual(InitialsField(settings: settings).text, "")
    }

    // MARK: masked password field (secure UITextField whose edits the delegate applies itself)

    func test_secure_edit_inserts_at_the_caret_without_clearing() {
        // Typing into a masked field that already holds a value: UIKit would clear it; the edit is applied instead.
        let r = SecureEdit.apply(to: "hunter2", range: NSRange(location: 7, length: 0), replacement: "!")
        XCTAssertEqual(r.text, "hunter2!"); XCTAssertEqual(r.caret, 8)
        let mid = SecureEdit.apply(to: "abcd", range: NSRange(location: 2, length: 0), replacement: "X")
        XCTAssertEqual(mid.text, "abXcd"); XCTAssertEqual(mid.caret, 3)
    }

    func test_secure_edit_delete_replace_and_paste() {
        let del = SecureEdit.apply(to: "abcd", range: NSRange(location: 3, length: 1), replacement: "")
        XCTAssertEqual(del.text, "abc"); XCTAssertEqual(del.caret, 3)
        let rep = SecureEdit.apply(to: "abcdef", range: NSRange(location: 1, length: 3), replacement: "Z")
        XCTAssertEqual(rep.text, "aZef"); XCTAssertEqual(rep.caret, 2)
        let paste = SecureEdit.apply(to: "", range: NSRange(location: 0, length: 0), replacement: "p@ss w0rd")
        XCTAssertEqual(paste.text, "p@ss w0rd"); XCTAssertEqual(paste.caret, 9)
        let all = SecureEdit.apply(to: "old", range: NSRange(location: 0, length: 3), replacement: "new")
        XCTAssertEqual(all.text, "new"); XCTAssertEqual(all.caret, 3)
    }

    func test_secure_edit_counts_utf16_like_uikit() {
        // "é" is one UTF-16 unit, "😀" two: ranges from UIKit are UTF-16.
        let r = SecureEdit.apply(to: "a😀b", range: NSRange(location: 1, length: 2), replacement: "é")
        XCTAssertEqual(r.text, "aéb"); XCTAssertEqual(r.caret, 2)
        let bad = SecureEdit.apply(to: "ab", range: NSRange(location: 5, length: 1), replacement: "x")
        XCTAssertEqual(bad.text, "ab", "an out-of-range edit changes nothing")
    }

    func test_secure_field_is_configured_for_secure_entry() {
        let tf = SecureInputField.makeTextField(placeholder: "Password", keyboard: .numberPad)
        XCTAssertTrue(tf.isSecureTextEntry)
        XCTAssertEqual(tf.textContentType, .oneTimeCode)
        XCTAssertEqual(tf.autocorrectionType, .no)
        XCTAssertEqual(tf.spellCheckingType, .no)
        XCTAssertEqual(tf.smartQuotesType, .no)
        XCTAssertEqual(tf.smartDashesType, .no)
        XCTAssertEqual(tf.smartInsertDeleteType, .no)
        XCTAssertEqual(tf.autocapitalizationType, .none)
        XCTAssertEqual(tf.keyboardType, .numberPad)
        XCTAssertEqual(tf.attributedPlaceholder?.string, "Password")
        XCTAssertFalse(tf.clearsOnBeginEditing)
    }

    func test_revealed_or_composing_input_is_left_to_uikit() {
        XCTAssertTrue(SecureInputField.Coordinator.appliesEditItself(secure: true, composing: false))
        XCTAssertFalse(SecureInputField.Coordinator.appliesEditItself(secure: true, composing: true), "IME composition")
        XCTAssertFalse(SecureInputField.Coordinator.appliesEditItself(secure: false, composing: false), "revealed")
        XCTAssertFalse(SecureInputField.Coordinator.appliesEditItself(secure: false, composing: true))

        var value = "abc"
        let tf = SecureInputField.makeTextField(placeholder: "Password", keyboard: .default)
        tf.isSecureTextEntry = false   // the eye button
        tf.text = value
        let coordinator = SecureInputField.Coordinator(text: { value }, set: { value = $0 })
        let center = NotificationCenter.default
        var posted = 0
        let token = center.addObserver(forName: UITextField.textDidChangeNotification, object: tf, queue: nil) { _ in posted += 1 }
        defer { center.removeObserver(token) }
        XCTAssertTrue(coordinator.textField(tf, shouldChangeCharactersIn: NSRange(location: 3, length: 0), replacementString: "か"))
        XCTAssertEqual(value, "abc", "UIKit applies it; the binding follows on editingChanged")
        tf.text = "abcか"   // what UIKit does after returning true
        coordinator.editingChanged(tf)
        XCTAssertEqual(value, "abcか")
        XCTAssertEqual(posted, 1, "typing still counts as activity")
    }

    func test_delegate_applies_the_edit_and_refuses_uikits_own() {
        var value = "hunter2"
        let tf = SecureInputField.makeTextField(placeholder: "Password", keyboard: .default)
        tf.text = value
        let coordinator = SecureInputField.Coordinator(text: { value }, set: { value = $0 })
        let allowed = coordinator.textField(tf, shouldChangeCharactersIn: NSRange(location: 7, length: 0), replacementString: "9")
        XCTAssertFalse(allowed, "UIKit never applies (or clears) the text itself")
        XCTAssertEqual(value, "hunter29")
        XCTAssertEqual(tf.text, "hunter29")
        XCTAssertTrue(tf.isSecureTextEntry, "still secure entry")
    }
}
