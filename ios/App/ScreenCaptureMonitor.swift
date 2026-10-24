import UIKit
import Observation

/// Whether the screen is being recorded, mirrored (AirPlay) or shared (audit 2026-10-24 L-8). While it is,
/// revealed secrets are masked again and the eye buttons do nothing: item detail (`ItemDetailModel`) and the
/// editor's secret fields read `isCaptured`.
@MainActor
@Observable
final class ScreenCaptureMonitor {
    static let shared = ScreenCaptureMonitor()

    private(set) var isCaptured: Bool
    @ObservationIgnored private let read: @MainActor () -> Bool
    @ObservationIgnored private var observer: (any NSObjectProtocol)?

    /// - Parameter read: the current state; by default any connected window scene's screen reports
    ///   `isCaptured` (`UIScreen.main` is deprecated).
    init(center: NotificationCenter = .default, read: @escaping @MainActor () -> Bool = ScreenCaptureMonitor.anySceneCaptured) {
        self.read = read
        isCaptured = read()
        observer = center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    /// Re-reads the state (on the notification, and when the app becomes active: a recording may have started
    /// while it was in the background).
    func refresh() {
        let now = read()
        if now != isCaptured { isCaptured = now }
    }

    static func anySceneCaptured() -> Bool {
        UIApplication.shared.connectedScenes.contains { ($0 as? UIWindowScene)?.screen.isCaptured == true }
    }
}
