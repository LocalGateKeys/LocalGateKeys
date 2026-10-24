import SwiftUI
import UIKit

/// Idle-lock activity that never competes for touches: a window-level recogniser that only watches touches
/// begin (sheets, the editor, Settings and the generator are in the same window), plus text-change
/// notifications for typing (the keyboard lives in its own window, so its taps never reach ours).
@MainActor
final class ActivityMonitor {
    private let onActivity: @MainActor () -> Void
    /// Written only in init; read in deinit (NotificationCenter removal is thread-safe).
    nonisolated(unsafe) private var observers: [NSObjectProtocol] = []
    private let recognizer: ActivityTouchRecognizer

    init(center: NotificationCenter = .default, onActivity: @escaping @MainActor () -> Void) {
        self.onActivity = onActivity
        self.center = center
        recognizer = ActivityTouchRecognizer()
        recognizer.onTouch = { [weak self] in self?.onActivity() }
        for name in [UITextField.textDidChangeNotification, UITextView.textDidChangeNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.onActivity() }
            })
        }
    }

    private let center: NotificationCenter

    deinit {
        for o in observers { center.removeObserver(o) }
    }

    /// Adds the recogniser to `window` (once; moving it from an earlier window).
    func attach(to window: UIWindow) {
        guard recognizer.view !== window else { return }
        recognizer.view?.removeGestureRecognizer(recognizer)
        window.addGestureRecognizer(recognizer)
    }
}

/// Reports every touch that begins and then fails at once, so it never recognises, never cancels or delays
/// a touch and never blocks another recogniser (List-row buttons, sheets, scroll views keep working).
final class ActivityTouchRecognizer: UIGestureRecognizer, UIGestureRecognizerDelegate {
    var onTouch: (@MainActor () -> Void)?

    init() {
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        onTouch?()
        state = .failed
    }

    override func canPrevent(_ preventedGestureRecognizer: UIGestureRecognizer) -> Bool { false }
    override func canBePrevented(by preventingGestureRecognizer: UIGestureRecognizer) -> Bool { false }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }
}

/// Hands the hosting window to the monitor; a zero-size, non-interactive background view.
struct ActivityWindowReader: UIViewRepresentable {
    let monitor: ActivityMonitor

    final class ReaderView: UIView {
        var onWindow: ((UIWindow) -> Void)?
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let window { onWindow?(window) }
        }
    }

    func makeUIView(context: Context) -> ReaderView {
        let v = ReaderView()
        v.isUserInteractionEnabled = false
        v.onWindow = { [monitor] in monitor.attach(to: $0) }
        return v
    }

    func updateUIView(_ uiView: ReaderView, context: Context) {}
}
