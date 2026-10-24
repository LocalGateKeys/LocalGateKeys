import UIKit

/// Keeps the app running while it holds the store's `flock` in the app-group container: iOS kills an app
/// suspended while holding a file lock there (0xdead10cc). Sync runs and editor/delete commits run inside
/// one. Tests use a fake that records `begin`/`end` pairing.
@MainActor
protocol BackgroundTasking: AnyObject {
    /// Starts a task; `expiration` is called if iOS is about to suspend the app before `end`.
    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int
    func end(_ token: Int)
}

@MainActor
final class UIKitBackgroundTasks: BackgroundTasking {
    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int {
        let id = UIApplication.shared.beginBackgroundTask(withName: name) { MainActor.assumeIsolated { expiration() } }
        return id.rawValue
    }

    func end(_ token: Int) {
        let id = UIBackgroundTaskIdentifier(rawValue: token)
        if id != .invalid { UIApplication.shared.endBackgroundTask(id) }
    }
}

/// One background task, ended exactly once: by `end()` or, on expiry, after `onExpire` ran.
@MainActor
final class BackgroundTaskScope {
    private let tasks: any BackgroundTasking
    private var token: Int?

    init(_ tasks: any BackgroundTasking, name: String, onExpire: @escaping @MainActor () -> Void = {}) {
        self.tasks = tasks
        token = tasks.begin(name) { [weak self] in
            onExpire()
            self?.end()
        }
    }

    func end() {
        guard let t = token else { return }
        token = nil
        tasks.end(t)
    }
}

extension BackgroundTasking {
    /// Runs `body` (a short synchronous commit) inside a background task.
    func run<T>(_ name: String, _ body: () throws -> T) rethrows -> T {
        let scope = BackgroundTaskScope(self, name: name)
        defer { scope.end() }
        return try body()
    }
}
