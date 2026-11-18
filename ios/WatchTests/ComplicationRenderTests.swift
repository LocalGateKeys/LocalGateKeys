import XCTest
import SwiftUI
import WidgetKit
import LGKCore

/// PENDING "Apple Watch" complication, what a simulator can show: the timeline changes at :00 and :30, the
/// codeless states, and every state rendered at 41 mm and 46 mm (rectangular and circular), in English,
/// normal, wrist down and redacted. With `LGK_SHOTS` set (TEST_RUNNER_LGK_SHOTS), the PNGs are written there.
@MainActor
final class ComplicationRenderTests: XCTestCase {
    let secret = "JBSWY3DPEHPK3PXP"
    /// accessoryRectangular / accessoryCircular in points: 41 mm (smallest supported here) and 46 mm.
    let sizes: [(String, CGSize, CGFloat)] = [("41mm", CGSize(width: 162, height: 50), 42),
                                               ("46mm", CGSize(width: 187, height: 56), 50)]

    func test_timeline_changes_at_00_and_30_and_ends_codeless() {
        let now = Date(timeIntervalSince1970: 1_700_000_017)   // 17 s into a period
        let entries = CodeComplicationProvider.entries(now: now, read: .codes([WatchCode(id: "a", title: "GitHub", secret: secret)]))
        XCTAssertEqual(entries.count, CodeComplicationProvider.entryCount + 1)
        XCTAssertEqual(entries.first?.date, now)
        for e in entries.dropFirst() {
            XCTAssertEqual(Int(e.date.timeIntervalSince1970) % 30, 0, "each later entry starts at :00 or :30")
        }
        XCTAssertEqual(entries.last?.content, .openApp)
        let codes = entries.compactMap { if case .code(let s) = $0.content { return s.code } else { return nil } }
        XCTAssertGreaterThan(Set(codes).count, 50, "the code changes every period")
        XCTAssertLessThanOrEqual(entries.last!.date.timeIntervalSince(now), 30 * 60, "never a code past 30 minutes")
    }

    func test_codeless_states() {
        let now = Date()
        XCTAssertEqual(CodeComplicationProvider.entries(now: now, read: .locked).map(\.content), [.locked])
        XCTAssertEqual(CodeComplicationProvider.entries(now: now, read: .nothing).map(\.content), [.empty])
        XCTAssertEqual(CodeComplicationProvider.entries(now: now, read: .codes([])).map(\.content), [.empty])
    }

    func test_german_messages() {
        func de(_ key: String.LocalizationValue) -> String { String(localized: key, locale: Locale(identifier: "de")) }
        // The watch test bundle carries no strings: compare only when German is there.
        let locked = de("Unlock Apple Watch to see codes")
        if locked != "Unlock Apple Watch to see codes" {
            XCTAssertEqual(locked, "Apple Watch entsperren, um Codes zu sehen")
            XCTAssertEqual(de("2FA code"), "2FA-Code")
        }
    }

    private func entry(_ content: CodeComplicationEntry.Content) -> CodeComplicationEntry {
        CodeComplicationEntry(date: Date(), content: content)
    }

    private var states: [(String, CodeComplicationEntry.Content)] {
        let now = Date()
        let span = CodeSpan(date: now, periodStart: now.addingTimeInterval(-10), end: now.addingTimeInterval(20),
                            title: "github.com", code: "745690")
        let long = CodeSpan(date: now, periodStart: now, end: now.addingTimeInterval(30),
                            title: "Ein sehr langer Kontoname", code: "12345678")
        return [("code", .code(span)), ("code8", .code(long)), ("empty", .empty), ("locked", .locked), ("openApp", .openApp)]
    }

    private func render(_ v: some View, size: CGSize) -> CGImage? {
        let r = ImageRenderer(content: v.frame(width: size.width, height: size.height)
            .background(Color.black).foregroundStyle(.white))
        r.scale = 2
        return r.cgImage
    }

    private func idealHeight(_ v: some View, width: CGFloat) -> CGFloat {
        let r = ImageRenderer(content: v.frame(width: width).fixedSize(horizontal: false, vertical: true))
        r.scale = 1
        return r.cgImage.map { CGFloat($0.height) } ?? .infinity
    }

    private func save(_ image: CGImage?, _ name: String) {
        guard let dir = ProcessInfo.processInfo.environment["LGK_SHOTS"], let image,
              let data = UIImage(cgImage: image).pngData() else { return }
        try? data.write(to: URL(fileURLWithPath: dir).appendingPathComponent("watch-\(name).png"))
    }

    func test_render_every_state_at_41_and_46_mm() {
        // English only: the unhosted watch test bundle has no app strings, so German would render as English.
        for locale in ["en"] {
            for (mm, rect, circle) in sizes {
                for (name, content) in states {
                    for (mode, wristDown, redacted) in [("normal", false, false), ("wristdown", true, false), ("redacted", false, true)] {
                        func v(_ family: WidgetFamily) -> some View {
                            CodeComplicationView(entry: entry(content), familyOverride: family)
                                .environment(\.locale, Locale(identifier: locale))
                                .environment(\.isLuminanceReduced, wristDown)
                                .redacted(reason: redacted ? .privacy : [])
                        }
                        let r = v(.accessoryRectangular)
                        // Code states shrink to fit (minimumScaleFactor), which an ideal height ignores: checked on the PNGs.
                        if mode == "normal", !name.hasPrefix("code") {
                            let h = idealHeight(r, width: rect.width)
                            XCTAssertLessThanOrEqual(h, rect.height, "\(name) \(locale) \(mm) rectangular clipped (\(h) pt)")
                        }
                        save(render(r, size: rect), "\(mm)-rect-\(locale)-\(name)-\(mode)")
                        save(render(v(.accessoryCircular), size: CGSize(width: circle, height: circle)),
                             "\(mm)-circ-\(locale)-\(name)-\(mode)")
                    }
                }
            }
        }
    }
}
