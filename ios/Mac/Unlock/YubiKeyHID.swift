import Foundation
import IOKit
import IOKit.hid

/// YubiKey HMAC-SHA1 challenge-response over USB HID (Mac, IOKit), the port of Windows `src/localvault/yubikey_hid.py`.
///
/// The YubiKey's OTP interface is a HID keyboard; commands go through 8-byte feature reports. The framing follows
/// Yubico's BSD-2-licensed sources (read for reference, not copied), as cited in `yubikey_hid.py`: yubikey-manager
/// `yubikit/core/otp.py` (CRC-16/X.25 with residual 0xF0B8, frame layout, status flags, the send/read/reset steps),
/// `yubikit/yubiotp.py` (CHAL_HMAC_1 = 0x30, CHAL_HMAC_2 = 0x38, DEVICE_SERIAL = 0x10), `ykman/hid/macos.py` (IOKit:
/// feature reports with report ID 0 and 8 bytes) and ykpers `ykcore/ykcore.c` (write order, touch wait).
///
/// A frame is 70 bytes: the 64-byte payload, the slot command, CRC16(payload) little-endian and 3 filler bytes.
/// `challengeResponse` sends the caller's 64 bytes exactly as given: the caller pads (`FactorSpec.paddedChallenge`,
/// COMPOSITE_KEY_V1 §1.2); this file never pads. It only sends the HMAC challenge and the read-only serial query,
/// never a configuration command.
enum YubiKeyOTP {
    static let yubicoVendorID = 0x1050
    /// Generic Desktop / Keyboard: the OTP interface (FIDO and CCID use other usages).
    static let usagePage = 0x01
    static let usage = 0x06
    static let featureReportSize = 8
    static let featureReportDataSize = 7
    static let slotDataSize = 64
    static let frameSize = slotDataSize + 6
    static let frameReports = frameSize / featureReportDataSize   // 10

    static let respPendingFlag: UInt8 = 0x40
    static let slotWriteFlag: UInt8 = 0x80
    static let respTimeoutWaitFlag: UInt8 = 0x20
    static let sequenceMask: UInt8 = 0x1F
    static let crcOKResidual: UInt16 = 0xF0B8

    static let cmdDeviceSerial: UInt8 = 0x10
    static func cmdChallengeHMAC(slot: Int) -> UInt8? { slot == 1 ? 0x30 : slot == 2 ? 0x38 : nil }
    static let hmacResponseSize = 20
    static let serialSize = 4
    /// Tells the key to drop a pending response (yubikit `_reset_state`).
    static let resetReport: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0xFF]

    /// CRC-16/X.25 (ISO 13239) without the final inversion, as the YubiKey computes it.
    static func crc(_ data: [UInt8]) -> UInt16 {
        var crc: UInt16 = 0xFFFF
        for byte in data {
            crc ^= UInt16(byte)
            for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0x8408 : crc >> 1 }
        }
        return crc
    }

    /// The 70-byte frame for `command` and the 64-byte `payload`.
    static func frame(command: UInt8, payload: [UInt8]) throws -> [UInt8] {
        guard payload.count == slotDataSize else { throw YubiKeyArgumentError("Frame payload must be 64 bytes") }
        let c = crc(payload)
        return payload + [command, UInt8(c & 0xFF), UInt8(c >> 8), 0, 0, 0]
    }

    /// The feature reports carrying `frame`: 7 data bytes + (0x80 | sequence); all-zero parts are skipped except the
    /// first and the last.
    static func reports(for frame: [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        for seq in 0..<frameReports {
            let part = Array(frame[(seq * featureReportDataSize)..<((seq + 1) * featureReportDataSize)])
            if seq == 0 || seq == frameReports - 1 || part.contains(where: { $0 != 0 }) {
                out.append(part + [slotWriteFlag | UInt8(seq)])
            }
        }
        return out
    }
}

/// Why the YubiKey did not answer. The codes are Windows `YubiKeyError.code`, plus `accessDenied` (macOS refused to
/// open the keyboard interface: the sandbox or Input Monitoring). None of them is a wrong password.
enum YubiKeyError: Error, Equatable, Sendable {
    case notFound, slotNotConfigured, touchTimeout, removed, busy, cancelled, accessDenied

    var code: String {
        switch self {
        case .notFound: "not_found"
        case .slotNotConfigured: "slot_not_configured"
        case .touchTimeout: "touch_timeout"
        case .removed: "removed"
        case .busy: "busy"
        case .cancelled: "cancelled"
        case .accessDenied: "access_denied"
        }
    }
}

/// A caller bug (a wrong slot or challenge length), never shown as a YubiKey problem.
struct YubiKeyArgumentError: Error, Equatable, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
}

/// An I/O failure on an open interface (unplugged mid-exchange): reported as `removed`.
struct YubiKeyIOError: Error, Equatable, Sendable { let status: Int32 }

struct YubiKeyInfo: Equatable, Sendable {
    let path: String
    let serial: UInt32?
    let version: [Int]
}

struct HIDDeviceInfo: Equatable, Sendable {
    let path: String
    let vendorID: Int
    let productID: Int
    let usagePage: Int
    let usage: Int
    let featureReportLength: Int
}

/// One open OTP interface. `receive` and `send` move one 8-byte feature report (throw on I/O failure).
protocol YubiKeyHIDTransport: AnyObject {
    func receive() throws -> [UInt8]
    func send(_ report: [UInt8]) throws
    func close()
}

/// The HID layer: IOKit live, a fake in the tests.
protocol YubiKeyHIDBackend: Sendable {
    func enumerate() -> [HIDDeviceInfo]
    /// Throws `YubiKeyError.notFound`, `.busy` or `.accessDenied`.
    func open(_ path: String) throws -> any YubiKeyHIDTransport
}

/// Thread-safe cancel flag for one exchange: the Cancel button and a lock set it from the main actor while the
/// exchange polls on a background thread.
final class YubiKeyCancel: @unchecked Sendable {
    private let condition = NSCondition()
    private var flag = false

    func cancel() {
        condition.lock()
        flag = true
        condition.broadcast()
        condition.unlock()
    }

    var isCancelled: Bool {
        condition.lock()
        defer { condition.unlock() }
        return flag
    }

    /// Waits up to `seconds`; true when cancelled (before or meanwhile).
    func wait(_ seconds: TimeInterval) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        if !flag { _ = condition.wait(until: Date().addingTimeInterval(seconds)) }
        return flag
    }
}

/// The OTP exchange over a `YubiKeyHIDBackend` (blocking: run it off the main actor).
struct YubiKeyHID: Sendable {
    let backend: any YubiKeyHIDBackend
    var pollInterval: TimeInterval = 0.02
    var touchPollInterval: TimeInterval = 0.1
    var writeReadyTries = 20
    var writeReadyInterval: TimeInterval = 0.05
    var serialTimeout: TimeInterval = 1.0
    var uptime: @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }

    /// One exchange at a time across the app: interleaved frames would corrupt both.
    private static let exchange = NSLock()

    static let live = YubiKeyHID(backend: IOKitHIDBackend())

    /// The 20-byte HMAC-SHA1 response of `slot` to the already padded 64-byte challenge.
    func challengeResponse(path: String, slot: Int, challenge64: [UInt8], timeout: TimeInterval = 15,
                           cancel: YubiKeyCancel? = nil) throws -> [UInt8] {
        guard let cmd = YubiKeyOTP.cmdChallengeHMAC(slot: slot) else { throw YubiKeyArgumentError("YubiKey slot must be 1 or 2") }
        guard challenge64.count == YubiKeyOTP.slotDataSize else {
            throw YubiKeyArgumentError("YubiKey challenge must be the 64-byte padded challenge")
        }
        guard Self.exchange.try() else { throw YubiKeyError.busy }
        defer { Self.exchange.unlock() }
        let transport = try backend.open(path)
        defer { transport.close() }
        do {
            return try command(transport, cmd, challenge64, expected: YubiKeyOTP.hmacResponseSize, timeout: timeout, cancel: cancel)
        } catch let e as YubiKeyError {
            throw e
        } catch {
            throw YubiKeyError.removed   // an I/O failure mid-exchange
        }
    }

    /// Plugged-in YubiKeys' OTP interfaces; the serial is nil when the key hides it or is busy.
    func listDevices() -> [YubiKeyInfo] {
        var found: [YubiKeyInfo] = []
        for info in backend.enumerate() where Self.isOTPInterface(info) {
            guard Self.exchange.try() else {
                found.append(YubiKeyInfo(path: info.path, serial: nil, version: [0, 0, 0]))
                continue
            }
            defer { Self.exchange.unlock() }
            do {
                found.append(try describe(info.path))
            } catch YubiKeyError.notFound {
                // gone between the listing and the open
            } catch {
                found.append(YubiKeyInfo(path: info.path, serial: nil, version: [0, 0, 0]))
            }
        }
        return found
    }

    /// macOS reports the feature report without its ID (8 bytes); Windows' 9 is accepted too.
    static func isOTPInterface(_ info: HIDDeviceInfo) -> Bool {
        info.vendorID == YubiKeyOTP.yubicoVendorID && info.usagePage == YubiKeyOTP.usagePage && info.usage == YubiKeyOTP.usage
            && (info.featureReportLength == YubiKeyOTP.featureReportSize || info.featureReportLength == YubiKeyOTP.featureReportSize + 1)
    }

    // MARK: - Exchange

    private func describe(_ path: String) throws -> YubiKeyInfo {
        let transport = try backend.open(path)
        defer { transport.close() }
        var version = [0, 0, 0]
        var serial: UInt32?
        do {
            let status = try receive(transport)
            version = [Int(status[1]), Int(status[2]), Int(status[3])]
            let bytes = try command(transport, YubiKeyOTP.cmdDeviceSerial, [UInt8](repeating: 0, count: YubiKeyOTP.slotDataSize),
                                    expected: YubiKeyOTP.serialSize, timeout: serialTimeout, cancel: nil)
            serial = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        } catch {
            // the version (if read) is still worth reporting; the serial stays unknown
        }
        return YubiKeyInfo(path: path, serial: serial, version: version)
    }

    private func receive(_ transport: any YubiKeyHIDTransport) throws -> [UInt8] {
        let report = try transport.receive()
        guard report.count == YubiKeyOTP.featureReportSize else { throw YubiKeyIOError(status: -1) }
        return report
    }

    private func reset(_ transport: any YubiKeyHIDTransport) {
        try? transport.send(YubiKeyOTP.resetReport)
    }

    private func sleep(_ seconds: TimeInterval, cancel: YubiKeyCancel?) -> Bool {
        if let cancel { return cancel.wait(seconds) }
        Thread.sleep(forTimeInterval: seconds)
        return false
    }

    private func sendFrame(_ transport: any YubiKeyHIDTransport, _ frame: [UInt8]) throws {
        for report in YubiKeyOTP.reports(for: frame) {
            var ready = false
            for _ in 0..<writeReadyTries {
                if try receive(transport)[YubiKeyOTP.featureReportDataSize] & YubiKeyOTP.slotWriteFlag == 0 { ready = true; break }
                Thread.sleep(forTimeInterval: writeReadyInterval)
            }
            guard ready else { throw YubiKeyError.busy }
            try transport.send(report)
        }
    }

    private func readResponse(_ transport: any YubiKeyHIDTransport, expected: Int, deadline: TimeInterval,
                              cancel: YubiKeyCancel?) throws -> [UInt8] {
        var response: [UInt8] = []
        var seq: UInt8 = 0
        var needsTouch = false
        while true {
            let report = try receive(transport)
            let status = report[YubiKeyOTP.featureReportDataSize]
            if status & YubiKeyOTP.respPendingFlag != 0 {
                if status & YubiKeyOTP.sequenceMask == seq {
                    response += report[0..<YubiKeyOTP.featureReportDataSize]
                    seq += 1
                } else if status & YubiKeyOTP.sequenceMask == 0 {   // transfer complete
                    reset(transport)
                    break
                }
            } else if status == 0 {   // a plain status report: the key has nothing to send
                if !response.isEmpty { throw YubiKeyError.removed }
                throw needsTouch ? YubiKeyError.touchTimeout : YubiKeyError.slotNotConfigured
            } else {
                needsTouch = needsTouch || status & YubiKeyOTP.respTimeoutWaitFlag != 0
                if sleep(needsTouch ? touchPollInterval : pollInterval, cancel: cancel) {
                    reset(transport)
                    throw YubiKeyError.cancelled
                }
            }
            if uptime() >= deadline {
                reset(transport)
                throw YubiKeyError.touchTimeout
            }
        }
        guard response.count >= expected + 2, YubiKeyOTP.crc(Array(response[0..<(expected + 2)])) == YubiKeyOTP.crcOKResidual else {
            throw YubiKeyError.removed   // broken transfer
        }
        return Array(response[0..<expected])
    }

    private func command(_ transport: any YubiKeyHIDTransport, _ command: UInt8, _ payload: [UInt8], expected: Int,
                         timeout: TimeInterval, cancel: YubiKeyCancel?) throws -> [UInt8] {
        let deadline = uptime() + timeout
        try sendFrame(transport, try YubiKeyOTP.frame(command: command, payload: payload))
        return try readResponse(transport, expected: expected, deadline: deadline, cancel: cancel)
    }
}

// MARK: - Responder

extension YubiKeyHID {
    static let busyRetryDelay: TimeInterval = 0.5

    /// The first plugged-in YubiKey's answer from `slot` (Windows `make_responder`): a busy key is retried once;
    /// `onTouch(true/false)` brackets the wait for a touch. Blocking: run it off the main actor.
    func respond(slot: Int, challenge64: [UInt8], cancel: YubiKeyCancel, onTouch: (Bool) -> Void) throws -> [UInt8] {
        for attempt in 1...2 {
            do {
                guard let device = listDevices().first else { throw YubiKeyError.notFound }
                onTouch(true)
                defer { onTouch(false) }
                return try challengeResponse(path: device.path, slot: slot, challenge64: challenge64, cancel: cancel)
            } catch YubiKeyError.busy where attempt == 1 && !cancel.isCancelled {
                if cancel.wait(Self.busyRetryDelay) { throw YubiKeyError.cancelled }
            }
        }
        throw YubiKeyError.busy
    }
}

// MARK: - IOKit

/// The live HID layer: `IOHIDManager` enumeration of Yubico devices and feature reports with report ID 0 (macOS
/// reports exclude the ID byte), as `ykman/hid/macos.py` does. Opening needs the sandbox's
/// `com.apple.security.device.usb` entitlement (Mac pending check: a signed sandboxed build opens the OTP interface).
struct IOKitHIDBackend: YubiKeyHIDBackend {
    // IOReturn values (`iokit_common_err`), not imported into Swift as constants.
    static let ioReturnExclusiveAccess = Int32(bitPattern: 0xE00002C5)
    static let ioReturnNotPermitted = Int32(bitPattern: 0xE00002E2)
    static let ioReturnNoDevice = Int32(bitPattern: 0xE00002C0)
    static let ioReturnNotPrivileged = Int32(bitPattern: 0xE00002C1)

    private func devices() -> [(path: String, device: IOHIDDevice)] {
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(0))
        IOHIDManagerSetDeviceMatching(manager, [kIOHIDVendorIDKey: YubiKeyOTP.yubicoVendorID] as CFDictionary)
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else { return [] }
        return set.compactMap { device -> (path: String, device: IOHIDDevice)? in
            var entryID: UInt64 = 0
            guard IORegistryEntryGetRegistryEntryID(IOHIDDeviceGetService(device), &entryID) == KERN_SUCCESS else { return nil }
            return ("IOService:\(entryID)", device)
        }
        .sorted { $0.path < $1.path }
    }

    private static func int(_ device: IOHIDDevice, _ key: String) -> Int {
        (IOHIDDeviceGetProperty(device, key as CFString) as? NSNumber)?.intValue ?? 0
    }

    func enumerate() -> [HIDDeviceInfo] {
        devices().map { entry in
            let d = entry.device
            return HIDDeviceInfo(path: entry.path, vendorID: Self.int(d, kIOHIDVendorIDKey), productID: Self.int(d, kIOHIDProductIDKey),
                                 usagePage: Self.int(d, kIOHIDPrimaryUsagePageKey), usage: Self.int(d, kIOHIDPrimaryUsageKey),
                                 featureReportLength: Self.int(d, kIOHIDMaxFeatureReportSizeKey))
        }
    }

    func open(_ path: String) throws -> any YubiKeyHIDTransport {
        guard let device = devices().first(where: { $0.path == path })?.device else { throw YubiKeyError.notFound }
        let status = IOHIDDeviceOpen(device, IOOptionBits(0))
        switch status {
        case kIOReturnSuccess: return IOKitHIDTransport(device: device)
        case Self.ioReturnExclusiveAccess: throw YubiKeyError.busy
        case Self.ioReturnNotPermitted, Self.ioReturnNotPrivileged: throw YubiKeyError.accessDenied
        default: throw YubiKeyError.notFound
        }
    }
}

final class IOKitHIDTransport: YubiKeyHIDTransport {
    private var device: IOHIDDevice?
    init(device: IOHIDDevice) { self.device = device }

    func receive() throws -> [UInt8] {
        guard let device else { throw YubiKeyIOError(status: IOKitHIDBackend.ioReturnNoDevice) }
        var buffer = [UInt8](repeating: 0, count: YubiKeyOTP.featureReportSize)
        var length = CFIndex(YubiKeyOTP.featureReportSize)
        let status = IOHIDDeviceGetReport(device, kIOHIDReportTypeFeature, 0, &buffer, &length)
        guard status == kIOReturnSuccess else { throw YubiKeyIOError(status: status) }
        return Array(buffer.prefix(max(0, min(length, buffer.count))))
    }

    func send(_ report: [UInt8]) throws {
        guard let device else { throw YubiKeyIOError(status: IOKitHIDBackend.ioReturnNoDevice) }
        let status = IOHIDDeviceSetReport(device, kIOHIDReportTypeFeature, 0, report, CFIndex(report.count))
        guard status == kIOReturnSuccess else { throw YubiKeyIOError(status: status) }
    }

    func close() {
        if let device { IOHIDDeviceClose(device, IOOptionBits(0)) }
        device = nil
    }
}
