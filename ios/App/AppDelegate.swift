import UIKit

/// UIKit hooks SwiftUI has no modifier for.
final class AppDelegate: NSObject, UIApplicationDelegate {
    /// No third-party keyboard ever sees what is typed here (master data, passwords, card numbers): the
    /// system keyboard is used instead (audit 2026-10-24 L-8). Other extension points are allowed.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        Self.allows(extensionPointIdentifier)
    }

    static func allows(_ extensionPoint: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPoint != .keyboard
    }
}
