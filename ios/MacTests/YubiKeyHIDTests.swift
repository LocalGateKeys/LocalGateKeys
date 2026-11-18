import XCTest
import CryptoKit
import LGKCore

// YubiKey HMAC-SHA1 challenge-response over USB HID (Mac/Unlock/YubiKeyHID.swift), the Windows tests
// (tests/test_yubikey_hid.py) ported. No hardware: `FakeYubiKey` plays the key's side of the OTP feature-report
// exchange (frame in 8-byte reports, status polling, response in 8-byte reports with a CRC) and computes HMAC-SHA1 the
// way a slot in variable-input mode does.

private let resetReport: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0xFF]
private let rfc2202Key = [UInt8](repeating: 0x0B, count: 20)
private let rfc2202Response = "b617318655057264e28bc0b6fb378c8ef146be00"

/// tests/vectors/composite_key/cases.json, "yubikey".
private enum Vector {
    static let hmacSecret = Array("vector-hmac-secret".utf8)
    static let paddedChallengeHex = "c05359d74919120739f641308863507d259ab55bd6401b04098c50989be6b5fb"
        + String(repeating: "20", count: 32)
    static let responseHex = "32c1c73745d1873a0dc5dfc174e7822e3e5e40f9"
}

private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

private func unhex(_ text: String) -> [UInt8] {
    var out: [UInt8] = []
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        out.append(UInt8(text[index..<next], radix: 16)!)
        index = next
    }
    return out
}

private func hiThere() -> [UInt8] { Array("Hi There".utf8) + [UInt8](repeating: 0, count: 56) }

/// Reference CRC (yubikey-manager yubikit/core/otp.py `calculate_crc`), kept apart from the code under test.
private func referenceCRC(_ data: [UInt8]) -> UInt16 {
    var crc: UInt16 = 0xFFFF
    for byte in data {
        crc ^= UInt16(byte)
        for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0x8408 : crc >> 1 }
    }
    return crc
}

/// A slot in variable-input mode: the trailing run of the last byte is padding.
private func variableModeHMAC(secret: [UInt8], payload: [UInt8]) -> [UInt8] {
    var message = payload
    if let last = message.last { while message.last == last { message.removeLast() } }
    return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
}

private struct FakeUnplugged: Error {}

/// The YubiKey side of the OTP HID protocol.
final class FakeYubiKey: YubiKeyHIDTransport, @unchecked Sendable {
    var slots: [Int: [UInt8]]
    var version: [UInt8]
    var serial: UInt32?
    var touchPolls: Int
    var deviceTouchTimeout: Bool
    var removeAfter: Int?
    var writeBusy: Bool
    private(set) var sent: [[UInt8]] = []
    private(set) var frames: [[UInt8]] = []
    private(set) var receives = 0
    private(set) var closed = false
    private(set) var waiting = 0
    private var frame = [UInt8](repeating: 0, count: 70)
    private var chunks: [[UInt8]]?
    private var next = 0

    init(slots: [Int: [UInt8]]? = nil, version: [UInt8] = [5, 4, 3], serial: UInt32? = 12_345_678, touchPolls: Int = 0,
         deviceTouchTimeout: Bool = false, removeAfter: Int? = nil, writeBusy: Bool = false) {
        self.slots = slots ?? [2: rfc2202Key]
        self.version = version; self.serial = serial; self.touchPolls = touchPolls
        self.deviceTouchTimeout = deviceTouchTimeout; self.removeAfter = removeAfter; self.writeBusy = writeBusy
    }

    private func status(_ byte: UInt8 = 0) -> [UInt8] { [0] + version + [1, 0x03, 0x00, byte] }

    func receive() throws -> [UInt8] {
        receives += 1
        if let removeAfter, receives > removeAfter { throw FakeUnplugged() }
        if writeBusy { return status(0x80) }
        guard let chunks else { return status() }
        if waiting > 0 {
            waiting -= 1
            if waiting == 0 && deviceTouchTimeout { self.chunks = nil }   // the key gave up waiting for a touch
            return status(0x20)
        }
        if next < chunks.count {
            let report = chunks[next] + [0x40 | UInt8(next)]
            next += 1
            return report
        }
        return [0, 0, 0, 0, 0, 0, 0, 0x40]   // sequence back to 0: transfer complete
    }

    func send(_ report: [UInt8]) throws {
        precondition(report.count == 8)
        if let removeAfter, receives > removeAfter { throw FakeUnplugged() }
        sent.append(report)
        if report == resetReport { chunks = nil; return }
        precondition(report[7] & 0x80 != 0)
        let seq = Int(report[7] & 0x1F)
        if seq == 0 { frame = [UInt8](repeating: 0, count: 70) }
        frame.replaceSubrange((seq * 7)..<(seq * 7 + 7), with: report[0..<7])
        if seq == 9 { process(frame) }
    }

    private func process(_ frame: [UInt8]) {
        frames.append(frame)
        let payload = Array(frame[0..<64]), command = frame[64]
        precondition(UInt16(frame[65]) | UInt16(frame[66]) << 8 == referenceCRC(payload))
        var body: [UInt8]
        switch command {
        case 0x10:
            guard let serial else { return }   // a key that hides its serial answers nothing
            body = withUnsafeBytes(of: serial.bigEndian, Array.init)
        case 0x30, 0x38:
            guard let secret = slots[command == 0x30 ? 1 : 2] else { return }   // unconfigured: a plain status report
            body = variableModeHMAC(secret: secret, payload: payload)
            waiting = touchPolls
        default:
            preconditionFailure("unexpected command \(command)")
        }
        let crc = referenceCRC(body) ^ 0xFFFF
        body += [UInt8(crc & 0xFF), UInt8(crc >> 8)]
        body += [UInt8](repeating: 0, count: (7 - body.count % 7) % 7)
        chunks = stride(from: 0, to: body.count, by: 7).map { Array(body[$0..<($0 + 7)]) }
        next = 0
    }

    func close() { closed = true }
}

/// `devices`: each interface and its key (nil: busy, held by another process); `busyOpens` refuses that many opens
/// first (a key another exchange holds for a moment).
final class FakeHIDBackend: YubiKeyHIDBackend, @unchecked Sendable {
    let devices: [(HIDDeviceInfo, FakeYubiKey?)]
    var busyOpens: Int
    init(_ devices: [(HIDDeviceInfo, FakeYubiKey?)], busyOpens: Int = 0) { self.devices = devices; self.busyOpens = busyOpens }

    func enumerate() -> [HIDDeviceInfo] { devices.map { $0.0 } }

    func open(_ path: String) throws -> any YubiKeyHIDTransport {
        if busyOpens > 0 { busyOpens -= 1; throw YubiKeyError.busy }
        guard let entry = devices.first(where: { $0.0.path == path }) else { throw YubiKeyError.notFound }
        guard let key = entry.1 else { throw YubiKeyError.busy }
        return key
    }
}

private func info(_ path: String, vendor: Int = 0x1050, usagePage: Int = 1, usage: Int = 6, feature: Int = 8) -> HIDDeviceInfo {
    HIDDeviceInfo(path: path, vendorID: vendor, productID: 0x0407, usagePage: usagePage, usage: usage, featureReportLength: feature)
}

private let otpPath = "IOService:4294969999"

private func hid(_ key: FakeYubiKey, path: String = otpPath) -> YubiKeyHID {
    YubiKeyHID(backend: FakeHIDBackend([(info(path), key)]), pollInterval: 0.001, touchPollInterval: 0.001, writeReadyInterval: 0.001)
}

private func assertYubiKeyError(_ expected: YubiKeyError, file: StaticString = #filePath, line: UInt = #line, _ op: () throws -> Void) {
    do { try op(); XCTFail("expected \(expected)", file: file, line: line) }
    catch { XCTAssertEqual(error as? YubiKeyError, expected, file: file, line: line) }
}

final class YubiKeyHIDTests: XCTestCase {
    /// Expected bytes computed with yubikey-manager's own yubikit/core/otp.py (main 4ca60f70) `calculate_crc`,
    /// `_format_frame` and `_should_send`: RFC 2202 case 1 ("Hi There"), slot 2 (the Windows vector).
    func testFrameAndCRCMatchReference() throws {
        let frame = try YubiKeyOTP.frame(command: 0x38, payload: hiThere())
        XCTAssertEqual(hex(frame), "4869205468657265" + String(repeating: "00", count: 56) + "380bac000000")
        XCTAssertEqual(YubiKeyOTP.reports(for: frame).map(hex), ["4869205468657280", "6500000000000081", "00380bac00000089"])
        let padded = (0..<32).map(UInt8.init) + [UInt8](repeating: 0x20, count: 32)
        XCTAssertEqual(hex(Array(try YubiKeyOTP.frame(command: 0x30, payload: padded)[64...])), "30cead000000")
        XCTAssertEqual(YubiKeyOTP.crc(hiThere()), 0xAC0B)
        XCTAssertEqual(YubiKeyOTP.crc(unhex(rfc2202Response + "5754")), YubiKeyOTP.crcOKResidual)
        XCTAssertThrowsError(try YubiKeyOTP.frame(command: 0x38, payload: [UInt8](repeating: 0, count: 32)))
    }

    func testChallengeResponseSlot2SendsThePaddedChallengeAsGiven() throws {
        let key = FakeYubiKey(slots: [2: Vector.hmacSecret])
        let padded = unhex(Vector.paddedChallengeHex)
        XCTAssertEqual(hex(try hid(key).challengeResponse(path: otpPath, slot: 2, challenge64: padded)), Vector.responseHex)
        XCTAssertEqual(Array(key.frames.last![0..<64]), padded)   // no library padding
        XCTAssertEqual(key.frames.last![64], 0x38)
        XCTAssertTrue(key.closed)
    }

    func testRFC2202VectorAndWrongArguments() throws {
        let h = hid(FakeYubiKey())
        XCTAssertEqual(hex(try h.challengeResponse(path: otpPath, slot: 2, challenge64: hiThere())), rfc2202Response)
        XCTAssertThrowsError(try h.challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 32))) {
            XCTAssertTrue($0 is YubiKeyArgumentError)
        }
        XCTAssertThrowsError(try h.challengeResponse(path: otpPath, slot: 3, challenge64: [UInt8](repeating: 0, count: 64))) {
            XCTAssertTrue($0 is YubiKeyArgumentError)
        }
    }

    func testSlot1CommandByte() throws {
        let secret = Array("slot one secret".utf8)
        let key = FakeYubiKey(slots: [1: secret])
        let padded = unhex(Vector.paddedChallengeHex)
        let expected = Array(HMAC<Insecure.SHA1>.authenticationCode(for: Array(padded[0..<32]), using: SymmetricKey(data: secret)))
        XCTAssertEqual(try hid(key).challengeResponse(path: otpPath, slot: 1, challenge64: padded), expected)
        XCTAssertEqual(key.frames.last![64], 0x30)
    }

    func testTouchWaitThenSuccess() throws {
        let key = FakeYubiKey(touchPolls: 5)
        XCTAssertEqual(hex(try hid(key).challengeResponse(path: otpPath, slot: 2, challenge64: hiThere())), rfc2202Response)
        XCTAssertEqual(key.waiting, 0)
    }

    func testTouchTimeout() {
        let key = FakeYubiKey(touchPolls: 1_000_000_000)
        assertYubiKeyError(.touchTimeout) {
            _ = try hid(key).challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64), timeout: 0.05)
        }
        XCTAssertEqual(key.sent.last, resetReport)
        XCTAssertTrue(key.closed)

        // The key's own touch timeout: it stops waiting and answers with a status report.
        let gaveUp = FakeYubiKey(touchPolls: 3, deviceTouchTimeout: true)
        assertYubiKeyError(.touchTimeout) {
            _ = try hid(gaveUp).challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64))
        }
    }

    func testSlotNotConfigured() {
        assertYubiKeyError(.slotNotConfigured) {
            _ = try hid(FakeYubiKey(slots: [1: Array("only slot one".utf8)]))
                .challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64))
        }
    }

    func testDeviceRemovedMidway() {
        let key = FakeYubiKey(touchPolls: 1_000_000_000, removeAfter: 6)
        assertYubiKeyError(.removed) {
            _ = try hid(key).challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64))
        }
        XCTAssertTrue(key.closed)
    }

    func testCancel() {
        let key = FakeYubiKey(touchPolls: 1_000_000_000)
        let cancel = YubiKeyCancel()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { cancel.cancel() }
        assertYubiKeyError(.cancelled) {
            _ = try hid(key).challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64),
                                                timeout: 10, cancel: cancel)
        }
        XCTAssertEqual(key.sent.last, resetReport)
    }

    func testBusyAndNotFound() {
        var busy = hid(FakeYubiKey(writeBusy: true))
        busy.writeReadyTries = 3
        assertYubiKeyError(.busy) {
            _ = try busy.challengeResponse(path: otpPath, slot: 2, challenge64: [UInt8](repeating: 0, count: 64))
        }
        assertYubiKeyError(.notFound) {
            _ = try busy.challengeResponse(path: "IOService:gone", slot: 2, challenge64: [UInt8](repeating: 0, count: 64))
        }
    }

    func testListFiltersYubicoOTPInterfaces() {
        let good = FakeYubiKey(version: [5, 7, 1], serial: 31337)
        let noSerial = FakeYubiKey(serial: nil)
        let backend = FakeHIDBackend([
            (info("yubikey-otp"), good),
            (info("other-vendor", vendor: 0x046D), FakeYubiKey()),
            (info("yubikey-fido", usagePage: 0xF1D0, usage: 1, feature: 0), FakeYubiKey()),
            (info("yubikey-wide-feature", feature: 65), FakeYubiKey()),
            (info("yubikey-locked"), nil),
            (info("yubikey-no-serial"), noSerial),
        ])
        let found = YubiKeyHID(backend: backend, pollInterval: 0.001, touchPollInterval: 0.001, writeReadyInterval: 0.001).listDevices()
        XCTAssertEqual(found, [
            YubiKeyInfo(path: "yubikey-otp", serial: 31337, version: [5, 7, 1]),
            YubiKeyInfo(path: "yubikey-locked", serial: nil, version: [0, 0, 0]),
            YubiKeyInfo(path: "yubikey-no-serial", serial: nil, version: [5, 4, 3]),
        ])
        XCTAssertTrue(good.closed)
        XCTAssertEqual(good.frames.last?[64], 0x10)   // the read-only serial query, nothing else
        XCTAssertEqual(good.frames.count, 1)
    }

    func testResponderRetriesABusyKeyOnceAndBracketsTheTouch() throws {
        let key = FakeYubiKey(slots: [2: Vector.hmacSecret])
        // The listing's open and the exchange's open are refused once each: the first attempt is busy.
        let backend = FakeHIDBackend([(info(otpPath), key)], busyOpens: 2)
        let h = YubiKeyHID(backend: backend, pollInterval: 0.001, touchPollInterval: 0.001, writeReadyInterval: 0.001)
        var touches: [Bool] = []
        let response = try h.respond(slot: 2, challenge64: unhex(Vector.paddedChallengeHex), cancel: YubiKeyCancel()) { touches.append($0) }
        XCTAssertEqual(hex(response), Vector.responseHex)
        XCTAssertEqual(touches, [true, false, true, false])

        let none = YubiKeyHID(backend: FakeHIDBackend([]))
        touches = []
        assertYubiKeyError(.notFound) {
            _ = try none.respond(slot: 2, challenge64: [UInt8](repeating: 0, count: 64), cancel: YubiKeyCancel()) { touches.append($0) }
        }
        XCTAssertEqual(touches, [])
    }

    /// The prompt's state machine: "Touch your YubiKey" while the key waits, Cancel stops the exchange, and the
    /// responder reports `cancelled` (the unlock then says nothing).
    @MainActor
    func testPromptShowsTouchAndCancelStopsTheExchange() async throws {
        let key = FakeYubiKey(touchPolls: 1_000_000_000)
        let prompt = YubiKeyPrompt(hid: hid(key))
        let respond = prompt.responder(slot: 2)
        let task = Task { try await respond(Data(unhex(Vector.paddedChallengeHex))) }
        for _ in 0..<500 where prompt.waitingSlot == nil { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(prompt.waitingSlot, 2)
        prompt.cancel()   // the Cancel button, and every lock (MacLockModel.lock)
        do { _ = try await task.value; XCTFail("expected cancelled") } catch { XCTAssertEqual(error as? YubiKeyError, .cancelled) }
        for _ in 0..<100 where prompt.waitingSlot != nil { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertNil(prompt.waitingSlot)
        XCTAssertNil(MacLockModel.describe(YubiKeyError.cancelled, now: Date()))
    }

    /// A cancel or lock that lands before the exchange starts stops it too: nothing is sent to the key.
    @MainActor
    func testCancelBeforeTheExchangeStartsSendsNothing() async throws {
        let key = FakeYubiKey(slots: [2: Vector.hmacSecret])
        let prompt = YubiKeyPrompt(hid: hid(key))
        let respond = prompt.responder(slot: 2)
        prompt.cancel()
        do { _ = try await respond(Data(unhex(Vector.paddedChallengeHex))); XCTFail("expected cancelled") }
        catch { XCTAssertEqual(error as? YubiKeyError, .cancelled) }
        XCTAssertTrue(key.frames.isEmpty)
        // A responder made after the cancel works.
        let again = try await prompt.responder(slot: 2)(Data(unhex(Vector.paddedChallengeHex)))
        XCTAssertEqual(hex([UInt8](again)), Vector.responseHex)
    }

    @MainActor
    func testPromptAnswersAndConfirmingResponderAsksTwice() async throws {
        let key = FakeYubiKey(slots: [2: Vector.hmacSecret])
        let prompt = YubiKeyPrompt(hid: hid(key))
        let response = try await prompt.confirmingResponder(slot: 2)(Data(unhex(Vector.paddedChallengeHex)))
        XCTAssertEqual(hex([UInt8](response)), Vector.responseHex)
        XCTAssertEqual(key.frames.filter { $0[64] == 0x38 }.count, 2)   // one challenge per touch (plus the listings' serial queries)
        XCTAssertFalse(prompt.touchAgain)
    }

    func testErrorMessagesFollowWindows() {
        XCTAssertEqual(MacFactors.yubiKeyMessage(.removed), "Touch your YubiKey again.")
        XCTAssertEqual(MacFactors.yubiKeyMessage(.touchTimeout), "No touch detected. Touch your YubiKey when it blinks.")
        XCTAssertTrue(MacFactors.yubiKeyMessage(.slotNotConfigured, slot: 2)?.contains("Yubico Authenticator") == true)
        XCTAssertTrue(MacFactors.yubiKeyMessage(.slotNotConfigured, slot: 1)?.contains("slot 1") == true)
        XCTAssertNil(MacFactors.yubiKeyMessage(.cancelled))
        XCTAssertEqual(MacFactors.factorMessage(.mismatch(.keyFile)), "This isn't the key file used for this vault.")
        XCTAssertEqual(MacFactors.factorMessage(.required([.keyFile, .yubiKeyHMAC])), "This vault also needs its key file and YubiKey.")
    }
}
