import SwiftUI
import UIKit

/// The part of a cover window the controller drives (a `UIWindow` in the app, a fake in tests).
@MainActor
protocol PrivacyCoverWindow: AnyObject {
    var isHidden: Bool { get set }
    /// False once the window's scene is gone or is no longer the app's scene: the controller builds a new one.
    var isOnCurrentScene: Bool { get }
}

extension UIWindow: PrivacyCoverWindow {
    var isOnCurrentScene: Bool {
        guard let scene = windowScene, scene.activationState != .unattached else { return false }
        return scene === PrivacyCoverController.currentScene()
    }
}

/// The app-switcher privacy cover in its own window above everything the app shows, presented sheets
/// (editor, Settings, generator) and alerts included: an overlay on the root view sits below them.
/// Shown as soon as the scene leaves `.active` (inactive or background), hidden again on `.active`.
@MainActor
final class PrivacyCoverController {
    private let makeWindow: @MainActor () -> (any PrivacyCoverWindow)?
    private var window: (any PrivacyCoverWindow)?
    private(set) var isCovering = false

    init(makeWindow: @escaping @MainActor () -> (any PrivacyCoverWindow)?) {
        self.makeWindow = makeWindow
    }

    func sceneChanged(_ phase: ScenePhase) {
        if phase == .active {
            window?.isHidden = true
            isCovering = false
            return
        }
        if let w = window, !w.isOnCurrentScene { w.isHidden = true; window = nil }   // scene gone or replaced
        if window == nil { window = makeWindow() }
        window?.isHidden = false
        isCovering = window != nil
    }

    /// Above alerts and sheets; never the key window, so focus and the keyboard stay with the app.
    static let windowLevel = UIWindow.Level.alert + 1

    static func configure(_ window: UIWindow) {
        window.windowLevel = windowLevel
        let host = UIHostingController(rootView: PrivacyCover())
        host.view.backgroundColor = .clear
        window.rootViewController = host
        window.isHidden = true
    }

    /// The live controller: one cover window on the app's window scene, made the first time it is needed.
    static func currentScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first(where: { $0.activationState != .unattached }) ?? scenes.first
    }

    static func live() -> PrivacyCoverController {
        PrivacyCoverController {
            guard let scene = currentScene() else { return nil }
            let window = UIWindow(windowScene: scene)
            configure(window)
            return window
        }
    }
}
