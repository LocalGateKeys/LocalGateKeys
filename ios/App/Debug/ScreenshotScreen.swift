import SwiftUI

#if DEBUG
/// DEBUG builds only: the screen to open after unlock, for App Store screenshots taken without taps.
/// Launch with `-LGKScreen item` (or `edit`: the item in its editor, `new`, `settings`, `upgrade`, `search`, `sync`, `security`, and on iPad `codes`), usually with `-LGKDemoData YES`.
enum ScreenshotScreen: String {
    case vault, item, edit, new, settings, upgrade, search, sync, security, codes

    static let launchArgument = "LGKScreen"
    static var requested: ScreenshotScreen? {
        UserDefaults.standard.string(forKey: launchArgument).flatMap(ScreenshotScreen.init(rawValue:))
    }
}
#endif

/// DEBUG builds only: `-LGKCompactWidth YES` gives the app a compact horizontal size class, as in Split View or
/// Slide Over at 1/3 width on iPad (UI tests cannot resize the window). Release builds ignore it.
struct ForcedCompactWidth: ViewModifier {
    func body(content: Content) -> some View {
        #if DEBUG
        if UserDefaults.standard.bool(forKey: "LGKCompactWidth") {
            content.environment(\.horizontalSizeClass, .compact)
        } else {
            content
        }
        #else
        content
        #endif
    }
}
