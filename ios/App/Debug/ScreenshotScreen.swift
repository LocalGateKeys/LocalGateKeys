#if DEBUG
import Foundation

/// DEBUG builds only: the screen to open after unlock, for App Store screenshots taken without taps.
/// Launch with `-LGKScreen item` (or `new`, `settings`, `upgrade`, `search`, `sync`, `security`), usually with `-LGKDemoData YES`.
enum ScreenshotScreen: String {
    case vault, item, new, settings, upgrade, search, sync, security

    static let launchArgument = "LGKScreen"
    static var requested: ScreenshotScreen? {
        UserDefaults.standard.string(forKey: launchArgument).flatMap(ScreenshotScreen.init(rawValue:))
    }
}
#endif
