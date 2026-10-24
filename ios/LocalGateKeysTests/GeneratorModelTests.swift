import XCTest
import SwiftUI
import UniformTypeIdentifiers
import AppShared
@testable import LocalGateKeys

@MainActor
final class GeneratorModelTests: XCTestCase {
    let clock = TestClock(1_800_000_000)
    var settings: AppSettings!
    var pasteboard: FakePasteboard!

    override func setUp() async throws {
        settings = AppSettings(defaults: UserDefaults(suiteName: "genmodel-\(UUID().uuidString)")!)
        pasteboard = FakePasteboard()
    }

    func model(random: any RandomSource = CountingRandom()) -> GeneratorModel {
        GeneratorModel(defaults: GeneratorDefaults(settings: settings), random: random,
                       clipboard: SecretClipboard(pasteboard: pasteboard, clock: clock, settings: settings))
    }

    func test_start_generates_from_saved_options() {
        var saved = GeneratorOptions(); saved.length = 31; saved.symbols = false
        GeneratorDefaults(settings: settings).save(saved)
        let m = model()
        XCTAssertEqual(m.options, saved)
        XCTAssertEqual(m.value, "", "nothing is generated before the sheet appears")
        m.start()
        XCTAssertEqual(m.value.count, 31)
        let first = m.value
        m.start()
        XCTAssertEqual(m.value, first, "appearing again keeps the value")
    }

    func test_regenerate_changes_the_value() {
        let m = model(); m.start()
        let first = m.value
        m.regenerate()
        XCTAssertNotEqual(m.value, first)
        XCTAssertEqual(m.value.count, 20)
    }

    func test_options_persist_and_regenerate() {
        let m = model(); m.start()
        let first = m.value
        m.options.mode = .passphrase
        XCTAssertNotEqual(m.value, first)
        XCTAssertEqual(m.value.split(separator: "-").count, 6)
        m.options.words = 4
        XCTAssertEqual(GeneratorDefaults(settings: settings).load().mode, .passphrase)
        XCTAssertEqual(GeneratorDefaults(settings: settings).load().words, 4)
        XCTAssertEqual(model().options, m.options, "a new sheet starts from them")
    }

    func test_bad_options_show_the_error_and_disable_use() {
        let m = model(); m.start()
        XCTAssertTrue(m.canUse)
        m.options.lowercase = false; m.options.uppercase = false; m.options.digits = false; m.options.symbols = false
        XCTAssertEqual(m.value, "")
        XCTAssertEqual(m.error, GeneratorError.noGroups.message)
        XCTAssertFalse(m.canUse)
        var dismissed = 0, delivered: [String] = []
        m.use(dismiss: { dismissed += 1 }, deliver: { delivered.append($0) })
        XCTAssertEqual(dismissed, 0); XCTAssertEqual(delivered, [])
        m.options.digits = true
        XCTAssertNil(m.error); XCTAssertTrue(m.canUse)
    }

    func test_strength_follows_the_options() {
        let m = model()
        XCTAssertEqual(m.strength, .veryStrong)
        m.options.mode = .passphrase; m.options.words = 3
        XCTAssertEqual(m.strength, GeneratorStrength.level(options: m.options))
        XCTAssertEqual(m.strength, .weak)
    }

    func test_copy_is_local_only_with_the_settings_expiry() {
        settings.clipboardExpiry = .twoMinutes
        let m = model(); m.start()
        m.copy()
        XCTAssertEqual(pasteboard.items.first?[UTType.utf8PlainText.identifier] as? String, m.value)
        XCTAssertEqual(pasteboard.options[.localOnly] as? Bool, true)
        XCTAssertEqual(pasteboard.options[.expirationDate] as? Date,
                       Date(timeIntervalSince1970: TimeInterval(clock.now + ClipboardExpiry.twoMinutes.rawValue)))
        XCTAssertTrue(m.copied)
        m.regenerate()
        XCTAssertFalse(m.copied, "a new value has not been copied")
    }

    func test_use_dismisses_first_then_delivers_to_the_editor_exactly_once() async throws {
        let store = MemoryStore(snapshot([]))
        let editor = EditorModel(store: store, pro: ProModel(purchases: FakePurchases(), licenseKeys: [:]), editing: nil,
                                 kind: .web, clock: clock, random: CountingRandom(), background: FakeBackgroundTasks())
        let m = model(); m.start()
        let value = m.value
        var events: [String] = []
        var delivered = 0
        let done = expectation(description: "delivered")
        let deliver: @MainActor (String) -> Void = { v in
            events.append("deliver"); delivered += 1
            editor.set("password", v)
            done.fulfill()
        }
        m.use(dismiss: { events.append("dismiss") }, deliver: deliver)
        XCTAssertEqual(events, ["dismiss"], "the value is delivered on a later main-actor turn, after dismiss")
        XCTAssertEqual(editor.value("password"), "")
        // A second tap while the sheet closes delivers nothing more.
        m.use(dismiss: { events.append("dismiss") }, deliver: deliver)
        XCTAssertFalse(m.canUse)
        await fulfillment(of: [done], timeout: 2)
        await Task.yield(); await Task.yield()
        XCTAssertEqual(events, ["dismiss", "deliver"])
        XCTAssertEqual(delivered, 1)
        XCTAssertEqual(editor.value("password"), value)
    }

    func test_length_slider_covers_8_to_64_and_keeps_a_longer_stepper_length() {
        var length = 100
        let b = GeneratorOptionsCard.sliderBinding(Binding(get: { length }, set: { length = $0 }),
                                                   in: GeneratorOptionsCard.sliderLengthRange)
        XCTAssertEqual(GeneratorOptionsCard.sliderLengthRange, 8...64)
        XCTAssertEqual(b.wrappedValue, 64, "thumb at the end")
        b.wrappedValue = 64
        XCTAssertEqual(length, 100, "the slider reporting its end position does not cut the length")
        b.wrappedValue = 31.6
        XCTAssertEqual(length, 32)
        b.wrappedValue = 8
        XCTAssertEqual(length, 8)
    }
}
