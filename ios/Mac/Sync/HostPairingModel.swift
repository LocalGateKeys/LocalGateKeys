import Foundation
import Observation
import LGKCore
import AppSharedMac

/// The Mac's side of Wi-Fi pairing (desktop `app/sync.py` `qr_show` / `qr_poll` / `qr_decide` / `qr_copy` /
/// `qr_close` and `lan_sync.LanResponder` enrollment): one offer shown as a QR code and as code text; a
/// device that proves it scanned it is shown with its name, 6-digit code and key fingerprint for Accept or
/// Decline (Decline by itself after 60 s); after Accept the device is pinned and can be removed again with Undo.
@MainActor
@Observable
final class HostPairingModel {
    enum Stage: Equatable { case idle, showing, confirm, adding, paired, declined, expired }

    /// A verified request waiting for Accept or Decline.
    struct Request: Equatable {
        let deviceID: String
        let name: String
        /// "123 456".
        let code: String
        /// The first 16 hex digits of its key fingerprint, in groups of four.
        let fingerprint: String
        let message: String
    }

    struct Paired: Equatable {
        let deviceID: String
        let name: String
        let fingerprint: String
        let message: String
    }

    // Windows copy (`app/sync.py`, `SyncPage.svelte`), "this Mac" for "this PC".
    static let acceptHint = String(localized: "Choose Accept only if the other device shows this same code.")
    static let declineHint = String(localized: "Otherwise choose Decline.")
    static let undoHint = String(localized: "If you don't recognise it, choose Undo.")
    static let pairHint = String(localized: "Phone and Mac must be on the same Wi-Fi.")
    static let otherPCHint = String(localized: "On another PC, use Join by QR text and paste the code text instead.")
    static let copiedText = String(localized: "Code text copied.")
    static let closedText = String(localized: "This pairing code has closed.")
    static let notWaitingText = String(localized: "That request is no longer waiting. Show a new code to try again.")
    static let declinedText = String(localized: "Declined. The device was not added. Show a new code to try again.")
    static let notListeningText = String(localized: "Turn on Wi-Fi sync first.")
    static func confirmText(name: String, code: String) -> String { String(localized: "\(name) wants to join. Choose Accept only if it shows the code \(code).") }
    static func addingText(_ name: String) -> String { String(localized: "Adding \(name)…") }
    static func pairedText(name: String, fingerprint: String) -> String {
        fingerprint.isEmpty ? String(localized: "Paired: \(name). \(undoHint)")
            : String(localized: "Paired: \(name) (key \(fingerprint)). \(undoHint)")
    }
    static func declinesText(_ seconds: Int) -> String { String(localized: "Declines by itself in \(seconds) s.") }

    /// `format_verification_code`: "123456" -> "123 456"; empty when malformed.
    static func formatCode(_ code: String) -> String {
        guard code.count == 6, code.allSatisfy({ $0.isASCII && $0.isNumber }) else { return "" }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }

    /// `paired_fingerprint`: the first 16 hex digits in groups of four; empty when malformed.
    static func fingerprintText(_ hex: String) -> String {
        guard !hex.isEmpty, hex.allSatisfy({ "0123456789abcdef".contains($0) }) else { return "" }
        let head = Array(hex.prefix(16))
        return stride(from: 0, to: head.count, by: 4).map { String(head[$0..<min($0 + 4, head.count)]) }.joined(separator: " ")
    }

    /// `countdown_text`.
    static func countdownText(_ secondsLeft: Int64) -> String {
        guard secondsLeft > 0 else { return String(localized: "Expired") }
        let clock = "\(secondsLeft / 60):" + String(format: "%02d", secondsLeft % 60)
        return String(localized: "Expires in \(clock)")
    }

    private(set) var stage: Stage = .idle
    /// The `lgk-pair:` text of the shown offer (the QR code's content, "Copy code text").
    private(set) var qrText: String?
    /// The offer's 8-digit code ("Code: …").
    private(set) var offerCode: String?
    private(set) var endpoint: LanEndpoint?
    private(set) var countdown = ""
    private(set) var request: Request?
    private(set) var secondsLeft: Int?
    private(set) var paired: Paired?
    private(set) var message: String?

    @ObservationIgnored let store: any ItemStore
    @ObservationIgnored let random: any RandomSource
    @ObservationIgnored let clock: any UnixClock
    @ObservationIgnored let monotonic: any MonotonicClock
    /// Desktop `ACCEPT_TIMEOUT_SECONDS`.
    @ObservationIgnored var acceptSeconds: Double = Double(Enrollment.acceptTimeoutSeconds)
    /// Called after a device was added (the host then syncs).
    @ObservationIgnored var onPaired: (() -> Void)?
    @ObservationIgnored private(set) var session: OfferSession?
    @ObservationIgnored private var decision: DecisionBox?
    @ObservationIgnored private var decisionDeadline: Double = 0

    init(store: any ItemStore, random: any RandomSource = SystemRandomSource(), clock: any UnixClock = SystemClock(),
         monotonic: any MonotonicClock = SystemMonotonicClock()) {
        self.store = store; self.random = random; self.clock = clock; self.monotonic = monotonic
    }

    var isOpen: Bool { session != nil && stage != .idle }

    /// `begin_pairing_job`: a Wi-Fi group when the vault has none yet, then a new offer reachable at `endpoint`.
    /// Returns the enrollment handler to install on the listener. Any earlier offer is closed first.
    func begin(endpoint: LanEndpoint, installID: String) throws -> any EnrollmentHandling {
        close()
        var snapshot = try store.load()
        if snapshot.sync == nil {
            let state = try SyncGroup.createWiFi(installID: installID, random: random)
            try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: snapshot.meta, sync: state))
            snapshot = try store.load()
        }
        guard let state = snapshot.sync else { throw SyncActionError("not-joined") }
        guard state.installID == installID else { throw SyncActionError("rejoin-required") }
        let (offer, _) = try PairingOffer.create(group: state.groupID, identity: state.identity, endpoint: endpoint, now: BoxedClock(base: clock),
                                                  random: BoxedRandom(base: random))
        return try arm(OfferSession(offer: offer, inviter: state.identity, wall: clock, monotonic: monotonic))
    }

    /// Shows `session`'s offer and returns its enrollment handler (`begin`; tests arm a recorded offer).
    func arm(_ session: OfferSession) throws -> any EnrollmentHandling {
        let offer = session.offer
        qrText = try offer.qrPayload()
        self.session = session
        offerCode = offer.code
        endpoint = offer.endpoint
        stage = .showing
        message = nil; request = nil; paired = nil; secondsLeft = nil
        countdown = Self.countdownText(offer.expiresAt - clock.now)
        return PairingEnrollment(session: session, store: store, random: random, clock: clock, model: self)
    }

    /// The timer tick (every second while the sheet is open): expire the offer, update the countdowns.
    func tick() {
        guard let session else { return }
        session.expire()
        let left = session.offer.expiresAt - clock.now
        countdown = Self.countdownText(left)
        if stage == .confirm { secondsLeft = max(0, Int((decisionDeadline - monotonic.seconds).rounded(.up))) }
        if stage == .showing && (left <= 0 || session.isExhausted) { stage = .expired; countdown = String(localized: "Expired") }
    }

    /// "Copy code text": the offer text while it is still open, else nil (and `closedText`).
    func copyCodeText() -> String? {
        guard let session, let qrText, [.showing, .confirm].contains(stage), session.offer.expiresAt > clock.now else {
            message = Self.closedText
            return nil
        }
        message = Self.copiedText
        return qrText
    }

    /// Accept or Decline the waiting request; false (and `notWaitingText`) when none waits.
    @discardableResult
    func decide(_ accept: Bool, deviceID: String) -> Bool {
        guard stage == .confirm, let decision, deviceID == request?.deviceID, decision.resolve(accept) else {
            message = Self.notWaitingText
            return false
        }
        return true
    }

    /// Close: disarm the offer (later requests get no answer); a request waiting for Accept is declined.
    func close() {
        session?.stop()
        decision?.resolve(false)
        decision = nil
        session = nil
        stage = .idle
        qrText = nil; offerCode = nil; endpoint = nil; request = nil; secondsLeft = nil; countdown = ""
    }

    /// Keep the device just added.
    func keep() {
        paired = nil
        if stage == .paired { stage = .idle }
    }

    /// Undo = Remove a device: the device just added is revoked (stays listed so its id cannot come back).
    @discardableResult
    func undo() -> Bool {
        guard let p = paired else { return false }
        do {
            let snap = try store.load()
            guard let state = snap.sync else { return false }
            let (revoked, found) = LanPeers.revoking(p.deviceID, in: state)
            guard found else { return false }
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: revoked))
        } catch {
            message = SyncWording.stepFailedCopy
            return false
        }
        paired = nil
        stage = .idle
        return true
    }

    // MARK: called by the enrollment handler

    /// A request verified: show it and wait for Accept or Decline (Decline after `acceptSeconds`).
    func ask(_ r: Enrollment.Request, session: OfferSession) async -> Bool {
        guard self.session === session else { return false }
        // One request at a time: a second one while the first waits for Accept is declined.
        guard decision == nil else { return false }
        let box = DecisionBox()
        decision = box
        decisionDeadline = monotonic.seconds + acceptSeconds
        let name = SyncWording.sanitize(r.name)
        let code = Self.formatCode(r.code)
        let fingerprint = Self.fingerprintText(LanPeer(deviceID: r.deviceID, groupID: session.offer.groupID,
                                                       signingPublic: r.signingPublic, exchangePublic: r.exchangePublic).fingerprint)
        request = Request(deviceID: r.deviceID, name: name, code: code, fingerprint: fingerprint,
                          message: Self.confirmText(name: name, code: code))
        secondsLeft = Int(acceptSeconds)
        stage = .confirm
        let wait = UInt64(max(0, acceptSeconds) * 1_000_000_000)
        let timeout = Task { try? await Task.sleep(nanoseconds: wait); box.resolve(false) }
        let accepted = await box.wait()
        timeout.cancel()
        if decision === box { decision = nil }
        guard self.session === session else { return false }
        secondsLeft = nil
        if accepted {
            stage = .adding
            message = Self.addingText(name)
        } else {
            stage = .declined
            request = nil
            message = Self.declinedText
        }
        return accepted
    }

    func didPair(_ r: Enrollment.Request, session: OfferSession) {
        guard self.session === session else { return }
        // Windows `short_id`: "Device 1a2b3c4d" (the name the device sent is not authenticated).
        let name = SyncWording.shortID(r.deviceID)
        let fingerprint = request?.fingerprint ?? ""
        paired = Paired(deviceID: r.deviceID, name: name, fingerprint: fingerprint, message: Self.pairedText(name: name, fingerprint: fingerprint))
        request = nil
        qrText = nil
        stage = .paired
        message = nil
        onPaired?()
    }

    func failed(reason: String, session: OfferSession) {
        guard self.session === session else { return }
        request = nil
        stage = .declined
        message = reason == "full" ? SyncWording.text(SyncIssue("too-many-peers")) : SyncWording.stepFailedCopy
    }
}

/// Resolves once (Accept, Decline, timeout or close); `wait` returns the first answer.
final class DecisionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Bool?
    private var waiter: CheckedContinuation<Bool, Never>?

    @discardableResult
    func resolve(_ accept: Bool) -> Bool {
        let (set, w): (Bool, CheckedContinuation<Bool, Never>?) = lock.withLock {
            guard value == nil else { return (false, nil) }
            value = accept
            defer { waiter = nil }
            return (true, waiter)
        }
        w?.resume(returning: accept)
        return set
    }

    func wait() async -> Bool {
        await withCheckedContinuation { c in
            let ready: Bool? = lock.withLock {
                if let value { return value }
                waiter = c
                return nil
            }
            if let ready { c.resume(returning: ready) }
        }
    }
}

/// The listener's enrollment handler for one offer (desktop `enroll_verify` → `await_decision` →
/// `enroll_finish`): verify (nothing pinned), ask on the Mac, then re-check against the current state, pin the
/// device and seal the group key to it. Pins nothing unless the user chose Accept.
struct PairingEnrollment: EnrollmentHandling {
    let session: OfferSession
    let store: any ItemStore
    let random: any RandomSource
    let clock: any UnixClock
    weak var model: HostPairingModel?

    static func refusal(_ reason: String) -> [UInt8] {
        (try? Enrollment.refusal(reason)) ?? (Enrollment.refusedMagic + Array(#"{"reason":"refused"}"#.utf8))
    }

    func enroll(_ raw: [UInt8]) async -> [UInt8]? {
        let state = (try? store.load())?.sync
        switch LanPeers.verifyEnrollment(raw, session: session, state: state) {
        case .refuse(let frame): return frame
        case .close: return nil
        case .verified(let request):
            guard let model, await model.ask(request, session: session) else { return Self.refusal("declined") }
            do {
                let snap = try store.load()
                guard let state = snap.sync else { throw PairingError.refused("refused") }
                let (reply, pinned) = try LanPeers.acceptEnrollment(request, offer: session.offer, state: state,
                                                                    now: clock.now, random: BoxedRandom(base: random))
                try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: pinned))
                await model.didPair(request, session: session)
                return reply
            } catch PairingError.refused(let reason) {
                await model.failed(reason: reason, session: session)
                return Self.refusal(reason)
            } catch {
                await model.failed(reason: "refused", session: session)
                return Self.refusal("refused")
            }
        }
    }
}

private struct BoxedClock: UnixClock {
    let base: any UnixClock
    var now: Int64 { base.now }
}

private struct BoxedRandom: RandomSource {
    let base: any RandomSource
    func bytes(count: Int) -> [UInt8] { base.bytes(count: count) }
}
