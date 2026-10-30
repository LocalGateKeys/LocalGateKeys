#if os(macOS)
import Foundation
#else
import UIKit
#endif

/// Keeps the app running while it holds the store's `flock` in the app-group container: iOS kills an app
/// suspended while holding a file lock there (0xdead10cc). Sync runs and editor/delete commits run inside
/// one. Tests use a fake that records `begin`/`end` pairing.
@MainActor
protocol BackgroundTasking: AnyObject {
    /// Starts a task; `expiration` is called if iOS is about to suspend the app before `end`.
    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int
    func end(_ token: Int)
}

#if os(macOS)
/// The Mac never suspends a running app; a commit is only held against App Nap and sudden termination.
@MainActor
final class MacActivityTasks: BackgroundTasking {
    private var activities: [Int: NSObjectProtocol] = [:]
    private var next = 1

    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int {
        defer { next += 1 }
        activities[next] = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .suddenTerminationDisabled], reason: name)
        return next
    }

    func end(_ token: Int) {
        if let a = activities.removeValue(forKey: token) { ProcessInfo.processInfo.endActivity(a) }
    }
}

@MainActor
enum PlatformBackgroundTasks {
    static func make() -> any BackgroundTasking { MacActivityTasks() }
}
#else
@MainActor
enum PlatformBackgroundTasks {
    static func make() -> any BackgroundTasking { UIKitBackgroundTasks() }
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
#endif

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
