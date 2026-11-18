import Foundation
import CoreNFC
import YubiKit
import AppShared

// The YubiKey factor of the iPhone app password over NFC (docs/formats/COMPOSITE_KEY_V1.md §1.2; Android
// `YubiKeyReader`, Mac `YubiKeyHID`). YubiKit (yubikit-ios 4.7.0) opens the NFC session and the ISO 7816 connection;
// the two APDUs are built here, so the 64-byte padded challenge goes to the key exactly as given (no library pads).
// Read-only: nothing is ever written to the key. Failures happen before any key derivation, so the app-password
// throttle never counts them.

/// A YubiKey problem over NFC. `cancelled` (the person closed the NFC sheet, or Cancel / a lock) says nothing.
enum YubiKeyNFCError: Error, Equatable, Sendable {
    /// This iPhone cannot read ISO 7816 NFC tags.
    case notAvailable
    /// The key left the field during the exchange: "Hold your YubiKey to the phone again".
    case tagLost
    /// No YubiKey was held to the phone before the NFC sheet timed out.
    case timeout
    /// The slot gave no answer (not set up for challenge-response), or the OTP applet is off.
    case slotNotConfigured(slot: Int)
    case cancelled
}

/// The CCID side of the OTP applet: SELECT, then the HMAC-SHA1 challenge (KeePassXC `YubiKeyInterfacePCSC.cpp`
/// `getHMAC`; YubiKit's own `YKFHMAC1ChallengeResponseAPDU` sends the same bytes).
enum YubiKeyAPDU {
    /// The OTP / challenge-response applet, as YubiKit selects it (the Info.plist select-identifiers list it).
    static let otpAID: [UInt8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01]

    static var selectOTP: Data { Data([0x00, 0xA4, 0x04, 0x00, UInt8(otpAID.count)] + otpAID) }

    /// `00 01 P1 00 40 ‖ padded challenge`, P1 = 0x30 (slot 1) or 0x38 (slot 2). `padded` must be the full 64-byte
    /// `FactorSpec.paddedChallenge` (anything else is refused, never padded here).
    static func challenge(slot: Int, padded: Data) -> Data? {
        guard padded.count == CompositeKey.paddedChallengeSize, slot == 1 || slot == 2 else { return nil }
        return Data([0x00, 0x01, slot == 1 ? 0x30 : 0x38, 0x00, UInt8(CompositeKey.paddedChallengeSize)]) + padded
    }

    /// A response's body and its status word (the last two bytes); nil when it is shorter than a status word.
    static func split(_ response: Data) -> (body: Data, sw: UInt16)? {
        guard response.count >= 2 else { return nil }
        let bytes = [UInt8](response)
        let sw = UInt16(bytes[bytes.count - 2]) << 8 | UInt16(bytes[bytes.count - 1])
        return (Data(bytes.prefix(bytes.count - 2)), sw)
    }
}

/// Sends one APDU and returns the response with its status word. The app's is the YubiKit NFC connection; tests use
/// a fake that records the bytes on the wire.
protocol YubiKeyAPDUTransport: Sendable {
    func transmit(_ apdu: Data) async throws -> Data
}

enum YubiKeyNFC {
    /// The 20-byte answer of `slot` to `challenge` (the full 64-byte padded challenge) over an open connection.
    static func respond(over transport: any YubiKeyAPDUTransport, slot: Int, challenge: Data) async throws -> Data {
        guard let command = YubiKeyAPDU.challenge(slot: slot, padded: challenge) else {
            throw YubiKeyNFCError.slotNotConfigured(slot: slot)
        }
        guard let selected = YubiKeyAPDU.split(try await transport.transmit(YubiKeyAPDU.selectOTP)), selected.sw == 0x9000 else {
            throw YubiKeyNFCError.slotNotConfigured(slot: slot)
        }
        // An empty body (or a refused command) is the OTP applet's "no data": the slot is not set up.
        guard let answer = YubiKeyAPDU.split(try await transport.transmit(command)), answer.sw == 0x9000, !answer.body.isEmpty else {
            throw YubiKeyNFCError.slotNotConfigured(slot: slot)
        }
        return answer.body
    }

    /// What an NFC session or transport error means here: the person's cancel, the sheet's timeout, else a lost tag.
    static func failure(_ error: Error) -> YubiKeyNFCError {
        if let e = error as? YubiKeyNFCError { return e }
        if let e = error as? NFCReaderError {
            switch e.code {
            case .readerSessionInvalidationErrorUserCanceled: return .cancelled
            case .readerSessionInvalidationErrorSessionTimeout: return .timeout
            case .readerErrorUnsupportedFeature: return .notAvailable
            default: return .tagLost
            }
        }
        if error is CancellationError { return .cancelled }
        return .tagLost
    }
}

/// An open connection handed from YubiKit's delegate to the waiting exchange. YubiKit's `YKFNFCConnection` is not
/// Sendable; it is only used through its serial command queue, so the box crosses tasks unchecked.
struct ConnectionBox: @unchecked Sendable {
    let transport: any YubiKeyAPDUTransport
}

/// Starts and stops the NFC session. The app's drives YubiKit's shared manager; tests drive the reader by hand.
protocol NFCSessionDriving: AnyObject, Sendable {
    func start(delegate: YubiKeyNFCReader)
    /// Closes the session showing `message` (as an error when `failed`); nil closes it silently (a cancel).
    func stop(failed: Bool, message: String?)
}

final class YubiKitSessionDriver: NFCSessionDriving, @unchecked Sendable {
    func start(delegate: YubiKeyNFCReader) {
        DispatchQueue.main.async {
            YubiKitExternalLocalization.nfcScanAlertMessage = YubiKeyNFCReader.holdText
            YubiKitManager.shared.delegate = delegate
            YubiKitManager.shared.startNFCConnection()
        }
    }

    func stop(failed: Bool, message: String?) {
        DispatchQueue.main.async {
            switch (failed, message) {
            case (_, nil): YubiKitManager.shared.stopNFCConnection()
            case (true, let text?): YubiKitManager.shared.stopNFCConnection(withErrorMessage: text)
            case (false, let text?): YubiKitManager.shared.stopNFCConnection(withMessage: text)
            }
        }
    }
}

/// The NFC reader: one exchange at a time. Cancel (and every lock) ends a waiting exchange; a responder made before a
/// cancel never starts one afterwards (Mac `YubiKeyPrompt` generations). Each exchange closes its NFC session and
/// waits for the session's end callback (at most `closeTimeout`), each close tagged with its own token: a timer only
/// ends its own close, and the end callback of a closed session is used up by that close, so it never fails the next
/// exchange's connect (a renewed challenge asks again right after the check).
final class YubiKeyNFCReader: NSObject, YKFManagerDelegate, @unchecked Sendable {
    static let shared = YubiKeyNFCReader()

    private let driver: any NFCSessionDriving
    private let available: @Sendable () -> Bool
    private let closeTimeout: TimeInterval
    private let lock = NSLock()
    private var waiting: CheckedContinuation<ConnectionBox, Error>?
    /// The close waiting for its session's end callback, with its token.
    private var closing: (token: Int, done: CheckedContinuation<Void, Never>)?
    private var closeTokens = 0
    private var generation = 0

    init(driver: any NFCSessionDriving = YubiKitSessionDriver(), closeTimeout: TimeInterval = 2,
         available: @escaping @Sendable () -> Bool = { YubiKitDeviceCapabilities.supportsISO7816NFCTags }) {
        self.driver = driver; self.closeTimeout = closeTimeout; self.available = available
        super.init()
    }

    static var isAvailable: Bool { YubiKitDeviceCapabilities.supportsISO7816NFCTags }

    static var holdText: String { DeviceText.isPad ? String(localized: "ipad.factors.nfc.hold", defaultValue: "Hold your YubiKey to the top of your iPad.") : String(localized: "factors.nfc.hold", defaultValue: "Hold your YubiKey to the top of your iPhone.") }
    static var doneText: String { String(localized: "factors.nfc.done", defaultValue: "YubiKey read.") }

    /// Ends a waiting exchange (`YubiKeyNFCError.cancelled`) and closes the NFC sheet.
    func cancel() {
        let pending: CheckedContinuation<ConnectionBox, Error>? = lock.withLock {
            generation += 1
            defer { waiting = nil }
            return waiting
        }
        pending?.resume(throwing: YubiKeyNFCError.cancelled)
        driver.stop(failed: false, message: nil)
    }

    /// The `FactorSecrets.yubiKey` responder for `slot`: each call opens the NFC sheet for one tap.
    func responder(slot: Int) -> @Sendable (Data) async throws -> Data {
        let madeAt = lock.withLock { generation }
        return { [self] challenge in try await respond(slot: slot, challenge: challenge, madeAt: madeAt) }
    }

    /// A new YubiKey's responder: two taps that must agree (Windows `_TwoTouches`, Mac `confirmingResponder`).
    func confirmingResponder(slot: Int) -> @Sendable (Data) async throws -> Data {
        let respond = responder(slot: slot)
        return { challenge in
            let first = try await respond(challenge)
            let second = try await respond(challenge)
            guard PhoneFactors.sameBytes(first, second) else { throw PhoneFactors.touchesDiffer }
            return first
        }
    }

    private func respond(slot: Int, challenge: Data, madeAt: Int) async throws -> Data {
        guard available() else { throw YubiKeyNFCError.notAvailable }
        let box = try await connect(madeAt: madeAt)
        do {
            let answer = try await YubiKeyNFC.respond(over: box.transport, slot: slot, challenge: challenge)
            await close(failed: false, message: Self.doneText)
            return answer
        } catch {
            // A cancel or lock during the exchange ends it as a cancel, whatever the broken session reported.
            let current = lock.withLock { generation }
            let mapped = current == madeAt ? YubiKeyNFC.failure(error) : YubiKeyNFCError.cancelled
            await close(failed: true, message: PhoneFactors.yubiKeyMessage(mapped))
            throw mapped
        }
    }

    private func connect(madeAt: Int) async throws -> ConnectionBox {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<ConnectionBox, Error>) in
                lock.lock()
                guard madeAt == generation else {
                    lock.unlock()
                    cont.resume(throwing: YubiKeyNFCError.cancelled)
                    return
                }
                let previous = waiting
                waiting = cont
                lock.unlock()
                previous?.resume(throwing: YubiKeyNFCError.cancelled)
                driver.start(delegate: self)
            }
        } onCancel: {
            cancel()
        }
    }

    /// Closes the session and waits for its end callback, or `closeTimeout` (only this close's timer ends it).
    private func close(failed: Bool, message: String?) async {
        await withCheckedContinuation { (done: CheckedContinuation<Void, Never>) in
            let (token, previous): (Int, CheckedContinuation<Void, Never>?) = lock.withLock {
                closeTokens += 1
                let earlier = closing?.done
                closing = (closeTokens, done)
                return (closeTokens, earlier)
            }
            previous?.resume()
            driver.stop(failed: failed, message: message)
            DispatchQueue.main.asyncAfter(deadline: .now() + closeTimeout) { [self] in endClosing(token: token) }
        }
    }

    /// Ends the waiting close: any close for a session end callback (`token` nil), else only the close with `token`.
    /// True when a close was ended (the callback was that session's end).
    @discardableResult
    private func endClosing(token: Int? = nil) -> Bool {
        let done: CheckedContinuation<Void, Never>? = lock.withLock {
            guard let c = closing, token == nil || c.token == token else { return nil }
            closing = nil
            return c.done
        }
        done?.resume()
        return done != nil
    }

    private func finish(_ result: Result<ConnectionBox, Error>) -> Bool {
        let pending: CheckedContinuation<ConnectionBox, Error>? = lock.withLock {
            defer { waiting = nil }
            return waiting
        }
        pending?.resume(with: result)
        return pending != nil
    }

    // MARK: Session events (YubiKit's delegate calls these on the main thread; tests call them directly)

    /// A YubiKey connected. With no exchange waiting (it came after a cancel) the session is closed again.
    func connected(_ box: ConnectionBox) {
        if !finish(.success(box)) { driver.stop(failed: false, message: nil) }
    }

    /// The session ended (closed, failed, cancelled by the person). The end of a session this reader closed is used
    /// up by that close; otherwise it fails the waiting connect.
    func sessionEnded(_ error: Error?) {
        if endClosing() { return }
        _ = finish(.failure(error.map { YubiKeyNFC.failure($0) } ?? YubiKeyNFCError.cancelled))
    }

    // MARK: YKFManagerDelegate (YubiKit 4.7.0 `YubiKitManager.h`)

    func didConnectNFC(_ connection: YKFNFCConnection) { connected(ConnectionBox(transport: NFCTransport(connection: connection))) }
    func didDisconnectNFC(_ connection: YKFNFCConnection, error: Error?) { sessionEnded(error) }
    func didFailConnectingNFC(_ error: Error) { sessionEnded(error) }

    // NFC only: a 5Ci on Lightning needs the MFi accessory protocol, which this app does not declare.
    func didConnectAccessory(_ connection: YKFAccessoryConnection) {}
    func didDisconnectAccessory(_ connection: YKFAccessoryConnection, error: Error?) {}
}

/// YubiKit's raw APDU call on the NFC connection. The response ends with the status word: yubikit-ios 4.7.0
/// `YKFNFCConnection.m` `executeRawCommand` (lines 221-235) passes the controller's result, which
/// `YKFNFCConnectionController.m` builds as `responseData ‖ sw1 ‖ sw2` (lines 92-95).
private struct NFCTransport: YubiKeyAPDUTransport, @unchecked Sendable {
    let connection: YKFNFCConnection

    func transmit(_ apdu: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.executeRawCommand(apdu) { data, error in
                if let data { cont.resume(returning: data) } else { cont.resume(throwing: error ?? YubiKeyNFCError.tagLost) }
            }
        }
    }
}

/// The app's factor source: the key-file bookmark in the app-only Keychain group (readable before the unlock: with
/// the app password on, no slot but the local key carries `.userPresence`) and the NFC reader.
@MainActor
final class LivePhoneFactorSource: PhoneFactorSourcing {
    private let reader: YubiKeyNFCReader
    private lazy var keychain: any KeychainVault = {
        let group = AppKeychainVault.appOnlyGroup(configured: AppGroup.appKeychainAccessGroup) {
            _ = try SystemKeychainVault(accessGroup: $0).read(.installID)
        }
        return SystemKeychainVault(accessGroup: group ?? AppGroup.keychainAccessGroup)
    }()

    init(reader: YubiKeyNFCReader = .shared) { self.reader = reader }

    func rememberedKeyFile(check: String) -> RememberedKeyFile? {
        guard let mark = PhoneKeyFileBookmark.load(for: check, from: keychain), let url = mark.resolve(keychain: keychain) else { return nil }
        return RememberedKeyFile(name: mark.name, url: url)
    }

    func readKeyFile(_ url: URL) async throws -> Data {
        try await Task.detached(priority: .userInitiated) { try PhoneFactors.readKeyFile(url) }.value
    }

    func rememberKeyFile(_ url: URL, check: String) { try? PhoneKeyFileBookmark.save(url, check: check, to: keychain) }

    func forgetKeyFile() { PhoneKeyFileBookmark.forget(in: keychain) }

    func yubiKey(slot: Int, confirming: Bool) -> @Sendable (Data) async throws -> Data {
        confirming ? reader.confirmingResponder(slot: slot) : reader.responder(slot: slot)
    }

    func cancelYubiKey() { reader.cancel() }
}
