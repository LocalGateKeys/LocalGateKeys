import XCTest
import SwiftUI
import WidgetKit
import AppShared

/// PENDING iPhone "Lock Screen widgets", what a simulator can show: every state of the codes widget rendered in
/// English and German at the Lock Screen sizes, checked for clipping (the ideal height fits the family's height),
/// plus the redacted (locked) rendering. With `LGK_SHOTS` set (TEST_RUNNER_LGK_SHOTS), the PNGs are written there.
@MainActor
final class WidgetRenderTests: XCTestCase {
    /// Lock Screen rectangular sizes: 6.1" (iPhone 17e) and 6.3" (iPhone 17), in points.
    let rectangular: [CGSize] = [CGSize(width: 160, height: 72), CGSize(width: 172, height: 76)]
    let inline = CGSize(width: 234, height: 26)

    let states: [(String, CodesWidgetEntry.Content)] = [
        ("codes", .codes([CodesWidgetEntry.Code(title: "github.com", code: "123456"),
                          CodesWidgetEntry.Code(title: "Ein sehr langer Kontoname", code: "12345678"),
                          CodesWidgetEntry.Code(title: "mail", code: "654321")])),
        ("empty", .empty),
        ("phoneLocked", .phoneLocked),
        ("openApp", .openApp),
    ]

    private func view(_ content: CodesWidgetEntry.Content, family: WidgetFamily, locale: String,
                      redacted: Bool = false) -> some View {
        CodesWidgetView(entry: CodesEntry(date: Date(), content: content), familyOverride: family)
            .environment(\.locale, Locale(identifier: locale))
            .redacted(reason: redacted ? .privacy : [])
    }

    /// The height the view wants at `width` (its frames are flexible, so this is its content's height).
    private func idealHeight(_ v: some View, width: CGFloat) -> CGFloat {
        let r = ImageRenderer(content: v.frame(width: width).fixedSize(horizontal: false, vertical: true))
        r.scale = 1
        return r.uiImage?.size.height ?? .infinity
    }

    private func save(_ v: some View, size: CGSize, name: String) {
        guard let dir = ProcessInfo.processInfo.environment["LGK_SHOTS"] else { return }
        let r = ImageRenderer(content: v.frame(width: size.width, height: size.height)
            .background(Color.black).foregroundStyle(.white).environment(\.colorScheme, .dark))
        r.scale = 3
        if let data = r.uiImage?.pngData() {
            try? data.write(to: URL(fileURLWithPath: dir).appendingPathComponent("widget-\(name).png"))
        }
    }

    /// The German strings are the ones the widget shows (no English fallback, no raw key).
    func testGermanMessages() {
        func de(_ key: String) -> String {
            let bundle = Bundle.main.path(forResource: "de", ofType: "lproj").flatMap(Bundle.init(path:))
            return bundle?.localizedString(forKey: key, value: nil, table: nil) ?? key
        }
        XCTAssertEqual(de("Pin a code in LocalGateKeys"), "Heften Sie einen Code in LocalGateKeys an")
        XCTAssertEqual(de("Unlock iPhone to see codes"), "iPhone entsperren, um Codes zu sehen")
        XCTAssertEqual(de("Open LocalGateKeys to show codes"), "LocalGateKeys öffnen, um Codes anzuzeigen")
        XCTAssertEqual(de("Pinned codes"), "Angeheftete Codes")
    }

    func testRectangularStatesFitInEnglishAndGerman() {
        for locale in ["en", "de"] {
            for size in rectangular {
                for (name, content) in states {
                    let v = view(content, family: .accessoryRectangular, locale: locale)
                    let h = idealHeight(v, width: size.width)
                    XCTAssertLessThanOrEqual(h, size.height, "\(name) in \(locale) at \(size.width) pt is clipped (\(h) pt)")
                    save(v, size: size, name: "rect-\(Int(size.width))-\(locale)-\(name)")
                }
                save(view(states[0].1, family: .accessoryRectangular, locale: locale, redacted: true),
                     size: size, name: "rect-\(Int(size.width))-\(locale)-codes-redacted")
            }
        }
    }

    func testInlineStatesRender() {
        for locale in ["en", "de"] {
            for (name, content) in states {
                save(view(content, family: .accessoryInline, locale: locale), size: inline, name: "inline-\(locale)-\(name)")
            }
        }
    }

    /// A tap opens the app's Codes row (the URL the app routes to the Vault tab's Codes row).
    func testTapOpensTheCodesRow() {
        XCTAssertEqual(CodesTimeline.openURL.absoluteString, "localgatekeys://codes")
        XCTAssertTrue(CodesTimeline.isOpenURL(CodesTimeline.openURL))
    }

    /// The timeline's states: locked phone retries in 15 minutes and never keeps codes; a code timeline reloads at
    /// its end (the codeless entry), so a phone locked past the codes' end never shows an old code.
    func testReloadPolicies() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let locked = [CodesEntry(date: now, content: .phoneLocked)]
        XCTAssertEqual(String(describing: CodesTimelineProvider.policy(for: locked, now: now)),
                       String(describing: TimelineReloadPolicy.after(now.addingTimeInterval(15 * 60))))
        XCTAssertEqual(String(describing: CodesTimelineProvider.policy(for: [CodesEntry(date: now, content: .empty)], now: now)),
                       String(describing: TimelineReloadPolicy.never))
    }
}
