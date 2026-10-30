import Foundation

/// Monotonic seconds (never set back with the wall clock); tests inject fixed values.
public protocol MonotonicClock: Sendable {
    var seconds: Double { get }
}

public struct SystemMonotonicClock: MonotonicClock {
    public init() {}
    public var seconds: Double {
        var ts = timespec()
        clock_gettime(CLOCK_MONOTONIC, &ts)
        return Double(ts.tv_sec) + Double(ts.tv_nsec) / 1e9
    }
}

/// One armed pairing offer on the host (desktop `PairingSession` plus the offer timing of
/// `lan_sync.LanResponder.start_enrollment` / `enroll_verify` / `expire_enrollment`).
///
/// One success consumes the offer. A request that does not decrypt (size, magic, JSON shape, another
/// offer id, AES-GCM) is refused without counting, so a sender without the QR code cannot burn the
/// offer; once it decrypts, any failure counts, and after `maxAttempts` the offer is used up. The
/// lifetime runs on both the wall clock and the monotonic clock (setting the wall clock back cannot
/// extend it). For `graceSeconds` after expiry a late request gets `used-or-expired`; after that the
/// session stops and requests get no answer (`.close`).
public final class OfferSession: @unchecked Sendable {
    public static let maxAttempts = 5
    public static let graceSeconds: Double = 600

    public enum Outcome: Equatable, Sendable {
        /// Send this refusal frame (`LGKENROLLNO1\n...`).
        case refuse([UInt8])
        /// Close without an answer (no offer armed and the grace period is over).
        case close
        /// A verified request: show its name and code for Accept / Decline; nothing is pinned yet.
        case verified(Enrollment.Request)
    }

    public let offer: PairingOffer
    private let inviter: DeviceIdentity
    private let wall: any UnixClock
    private let monotonic: any MonotonicClock
    private let lock = NSLock()
    private var armed = true
    private var stopped = false
    private var consumed = false
    private var attemptCount = 0
    private let deadline: Double
    private let refuseUntil: Double

    public init(offer: PairingOffer, inviter: DeviceIdentity, wall: any UnixClock = SystemClock(),
                monotonic: any MonotonicClock = SystemMonotonicClock()) throws {
        guard inviter.deviceID == offer.inviterDeviceID, inviter.fingerprint == offer.certificateFingerprint,
              inviter.exchangePublicKey == offer.inviterExchangePublic else {
            throw PairingError.authentication("Inviter identity does not match the offer")
        }
        self.offer = offer
        self.inviter = inviter
        self.wall = wall
        self.monotonic = monotonic
        let mono = monotonic.seconds
        deadline = mono + max(0, Double(offer.expiresAt - wall.now))
        refuseUntil = deadline + Self.graceSeconds
    }

    public var attempts: Int { lock.withLock { attemptCount } }
    /// Used once, or `maxAttempts` failures.
    public var isExhausted: Bool { lock.withLock { consumed || attemptCount >= Self.maxAttempts } }
    /// True while requests still get an answer (armed, or within the grace period).
    public var isListening: Bool { lock.withLock { !stopped && monotonic.seconds < refuseUntil } }

    /// Disarm (Cancel, or a lock): later requests get no answer.
    public func stop() { lock.withLock { armed = false; stopped = true } }

    /// The timer tick: disarm an expired or used-up offer; stop after the grace period.
    public func expire() {
        lock.withLock {
            if monotonic.seconds >= refuseUntil { armed = false; stopped = true; return }
            if consumed || attemptCount >= Self.maxAttempts || expiredLocked() { armed = false }
        }
    }

    private func expiredLocked() -> Bool { wall.now >= offer.expiresAt || monotonic.seconds >= deadline }

    /// Every reason used here is in `Enrollment.refusalReasons`; an unknown one falls back to the generic frame.
    static func refusal(_ reason: String) -> Outcome {
        if let frame = try? Enrollment.refusal(reason) { return .refuse(frame) }
        return .refuse(Enrollment.refusedMagic + Array(#"{"reason":"refused"}"#.utf8))
    }

    /// One enrollment request. `reservedIDs` are device ids already in the group (they count as a
    /// failed attempt); `peerCount` >= `maxPeers` answers `full` before anything is consumed.
    public func handle(_ raw: [UInt8], reservedIDs: Set<String> = [], peerCount: Int = 0, maxPeers: Int = 16) -> Outcome {
        lock.lock(); defer { lock.unlock() }
        if stopped { return .close }
        let now = wall.now
        if now >= offer.expiresAt + Int64(Self.graceSeconds) || monotonic.seconds >= refuseUntil {
            armed = false; stopped = true
            return .close
        }
        if !armed || consumed || attemptCount >= Self.maxAttempts || expiredLocked() {
            return Self.refusal("used-or-expired")
        }
        if peerCount >= maxPeers { return Self.refusal("full") }
        let plain: [UInt8]
        do { plain = try Enrollment.decryptRequest(offer: offer, inviter: inviter, raw: raw) }
        catch { return Self.refusal("refused") }  // not counted
        do {
            let request = try Enrollment.verifyRequestBody(offer: offer, plain: plain)
            guard !reservedIDs.contains(request.deviceID) else {
                throw PairingError.authentication("This device id is already in use in the group")
            }
            consumed = true
            return .verified(request)
        } catch let error as PairingError {
            attemptCount += 1
            if case .refused("update-needed") = error { return Self.refusal("update-needed") }
            return Self.refusal("refused")
        } catch {
            attemptCount += 1
            return Self.refusal("refused")
        }
    }
}
