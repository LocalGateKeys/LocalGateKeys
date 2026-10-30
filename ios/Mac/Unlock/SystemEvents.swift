import AppKit
import CoreGraphics
import Foundation

/// The system events that lock the vault.
@MainActor
protocol SystemEvents: AnyObject {
    var screenLocked: AsyncStream<Void> { get }
    var willSleep: AsyncStream<Void> { get }
    /// Seconds since the last keyboard or mouse event anywhere on the Mac.
    func idleSeconds() -> TimeInterval
}

/// Screen lock from `com.apple.screenIsLocked`, sleep from `NSWorkspace.willSleepNotification`, idle time
/// from `CGEventSource`.
@MainActor
final class MacSystemEvents: SystemEvents {
    let screenLocked: AsyncStream<Void>
    let willSleep: AsyncStream<Void>
    private nonisolated(unsafe) var observers: [(NotificationCenter, NSObjectProtocol)] = []

    init() {
        let (locked, lockedCont) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let (sleep, sleepCont) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        screenLocked = locked; willSleep = sleep
        let dnc = DistributedNotificationCenter.default()
        observers.append((dnc, dnc.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            lockedCont.yield()
        }))
        let wnc = NSWorkspace.shared.notificationCenter
        observers.append((wnc, wnc.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { _ in
            sleepCont.yield()
        }))
    }

    deinit { for (center, token) in observers { center.removeObserver(token) } }

    func idleSeconds() -> TimeInterval {
        // kCGAnyInputEventType: the latest event of any type.
        CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
    }
}
