import Foundation
import AppKit
import Observation
import UniformTypeIdentifiers
import LGKCore
import AppSharedMac

// Key file and YubiKey factors on the Mac (docs/formats/COMPOSITE_KEY_V1.md, design §4.5-§4.7; Windows
// `src/localvault/app/factors.py`): bounded key-file reads, the per-vault key-file bookmark, the "Touch your YubiKey"
// state with its Cancel, and the messages. YubiKey failures happen before any key derivation, so the unlock throttle
// never counts them.

/// "Touch your YubiKey" while an exchange waits, for every screen (unlock, Settings, Recovery centre, a password
/// check). Cancel, and every lock, cancel the pending exchange.
@MainActor @Observable
final class YubiKeyPrompt {
    /// The slot being waited for; nil when no YubiKey is asked.
    private(set) var waitingSlot: Int?
    /// A new YubiKey answers twice: the second touch shows "Touch your YubiKey again to confirm".
    private(set) var touchAgain = false
    @ObservationIgnored private var pending: [YubiKeyCancel] = []
    /// Bumped by every `cancel()`: a responder made before a cancel or lock never starts an exchange afterwards.
    @ObservationIgnored private var generation = 0
    private let hid: YubiKeyHID

    init(hid: YubiKeyHID = .live) { self.hid = hid }

    /// The app's one prompt (the lock model's and every banner's).
    static let shared = YubiKeyPrompt()

    /// Cancels every pending exchange (the Cancel button, a lock).
    func cancel() {
        generation += 1
        for c in pending { c.cancel() }
        pending.removeAll()
        waitingSlot = nil
        touchAgain = false
    }

    /// False (and `cancel` set) when a cancel or lock came since the responder was made.
    private func begin(_ cancel: YubiKeyCancel, madeAt: Int) -> Bool {
        guard madeAt == generation else { cancel.cancel(); return false }
        pending.append(cancel)
        return true
    }
    private func end(_ cancel: YubiKeyCancel) {
        pending.removeAll { $0 === cancel }
        if pending.isEmpty { waitingSlot = nil; touchAgain = false }
    }
    private func touching(_ waiting: Bool, slot: Int) { waitingSlot = waiting ? slot : nil }
    func setTouchAgain(_ on: Bool) { touchAgain = on }

    /// The `FactorSecrets.yubiKey` responder for `slot` of the first plugged-in YubiKey. The exchange runs off the main
    /// actor; Cancel, a lock or the calling task's cancellation stop it (`YubiKeyError.cancelled`).
    func responder(slot: Int) -> @Sendable (Data) async throws -> Data {
        let hid = self.hid
        let madeAt = generation
        return { [weak self] challenge in
            let cancel = YubiKeyCancel()
            guard let self, await self.begin(cancel, madeAt: madeAt) else { throw YubiKeyError.cancelled }
            let onTouch: @Sendable (Bool) -> Void = { [weak self] waiting in
                // FIFO onto the main queue, so a quick true/false pair arrives in order.
                DispatchQueue.main.async { MainActor.assumeIsolated { self?.touching(waiting && !cancel.isCancelled, slot: slot) } }
            }
            do {
                let response = try await withTaskCancellationHandler {
                    try await Task.detached(priority: .userInitiated) {
                        Data(try hid.respond(slot: slot, challenge64: [UInt8](challenge), cancel: cancel, onTouch: onTouch))
                    }.value
                } onCancel: {
                    cancel.cancel()
                }
                await self.end(cancel)
                return response
            } catch {
                await self.end(cancel)
                throw error
            }
        }
    }

    /// A new YubiKey's responder: its answer is asked twice and both touches must agree (Windows `_TwoTouches`).
    func confirmingResponder(slot: Int) -> @Sendable (Data) async throws -> Data {
        let respond = responder(slot: slot)
        return { [weak self] challenge in
            let first = try await respond(challenge)
            await self?.setTouchAgain(true)
            let second: Data
            do { second = try await respond(challenge) } catch { await self?.setTouchAgain(false); throw error }
            await self?.setTouchAgain(false)
            guard MacFactors.sameBytes(first, second) else { throw MacFactors.touchesDiffer }
            return first
        }
    }
}

enum MacFactors {
    static let defaultSlot = 2

    /// Constant-time equality of two YubiKey answers.
    static func sameBytes(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    // MARK: Messages (Windows factors.*, vault.err.*; Mac wording where Windows names its own shortcuts)

    static var touchTitle: String { String(localized: "factors.prompt.touch", defaultValue: "Touch your YubiKey") }
    static var touchAgainTitle: String { String(localized: "factors.prompt.touchAgain", defaultValue: "Touch your YubiKey again to confirm") }
    static var touchText: String { String(localized: "factors.touchText", defaultValue: "Touch your YubiKey when it blinks.") }
    static var chooseKeyFileTitle: String { String(localized: "factors.chooseKeyFile", defaultValue: "Choose the vault's key file") }
    static var chooseKeyFileButton: String { String(localized: "factors.prompt.choose", defaultValue: "Choose key file…") }
    static var noKeyFileChosen: String { String(localized: "factors.prompt.noneChosen", defaultValue: "No key file chosen") }
    static func keyFileChosen(_ name: String) -> String { String(localized: "factors.prompt.chosen", defaultValue: "Key file: \(name)") }
    static func yubiKeyNeeded(slot: Int) -> String {
        let s = String(slot)
        return String(localized: "factors.prompt.yubikeyNeeded", defaultValue: "Insert your YubiKey (slot \(s)) and touch it when it blinks.")
    }
    static var rememberOnThisMac: String { String(localized: "factors.mac.remember", defaultValue: "Remember this key file on this Mac") }
    static var factorsRemovedByPhrase: String { String(localized: "recovery.factorsRemoved", defaultValue: "Key file / YubiKey removed; add them again.") }
    static var touchIDRemovedOnUnlock: String {
        String(localized: "factors.mac.touchIDRemovedOnUnlock",
               defaultValue: "Touch ID unlock was removed because \u{201C}Always ask for the key file / YubiKey\u{201D} is on.")
    }
    static var touchIDOff: String {
        String(localized: "factors.mac.shortcutsOff",
               defaultValue: "Touch ID is off while \u{201C}Always ask for the key file / YubiKey\u{201D} is on.")
    }
    static let touchesDiffer = FactorMessageError(String(localized: "factors.yubikeyTouchesDiffer",
                                                         defaultValue: "The two touches gave different answers. Use one YubiKey and try again."))
    static let keyFileTooLarge = FactorMessageError(String(localized: "recovery.keyFileTooLarge", defaultValue: "That file is too large to be a key file."))
    static func keyFileUnreadable(_ name: String) -> FactorMessageError {
        FactorMessageError(String(localized: "factors.keyFileUnreadable", defaultValue: "Could not read the key file \(name). Choose it again."))
    }
    static let alreadySet = FactorMessageError(String(localized: "vault.err.factorAlreadySet",
                                                      defaultValue: "This vault already has this kind of factor. Remove it first."))
    static let notSet = FactorMessageError(String(localized: "vault.err.factorNotSet", defaultValue: "This vault doesn't use this factor."))
    static let alwaysAskOn = FactorMessageError(touchIDOff)

    static func yubiKeyMessage(_ error: YubiKeyError, slot: Int = defaultSlot) -> String? {
        let s = String(slot)
        switch error {
        case .notFound: return String(localized: "factors.yubikey.notFound", defaultValue: "Insert your YubiKey and try again.")
        case .removed: return String(localized: "factors.yubikey.removed", defaultValue: "Touch your YubiKey again.")
        case .touchTimeout:
            return String(localized: "factors.yubikey.touchTimeout", defaultValue: "No touch detected. Touch your YubiKey when it blinks.")
        case .slotNotConfigured:
            return String(localized: "factors.yubikey.slotNotConfigured",
                          defaultValue: "Slot \(s) of this YubiKey is not set up for challenge-response. In Yubico Authenticator, choose Slots, then set slot \(s) to Challenge-response (HMAC-SHA1).")
        case .busy: return String(localized: "factors.yubikey.busy", defaultValue: "Your YubiKey is busy. Try again in a moment.")
        case .accessDenied:
            return String(localized: "factors.mac.yubikeyAccessDenied",
                          defaultValue: "macOS did not let LocalGateKeys use the YubiKey. Allow LocalGateKeys in System Settings › Privacy & Security › Input Monitoring, then try again.")
        case .cancelled: return nil   // the person's own choice: nothing to say
        }
    }

    static func factorMessage(_ error: FactorError) -> String {
        switch error {
        case .required(let kinds):
            let key = kinds.contains(.keyFile), yubi = kinds.contains(.yubiKeyHMAC)
            if key && yubi { return String(localized: "vault.err.factorRequiredBoth", defaultValue: "This vault also needs its key file and YubiKey.") }
            if yubi { return String(localized: "vault.err.factorRequiredYubiKey", defaultValue: "This vault also needs its YubiKey.") }
            return String(localized: "vault.err.factorRequiredKeyFile", defaultValue: "This vault also needs its key file.")
        case .mismatch(.keyFile):
            return String(localized: "vault.err.keyFileMismatch", defaultValue: "This isn't the key file used for this vault.")
        case .mismatch(.yubiKeyHMAC):
            return String(localized: "vault.err.yubiKeyMismatch", defaultValue: "This isn't the YubiKey used for this vault.")
        }
    }

    /// The line for a factor problem, `.some(nil)` for one that says nothing (a cancelled touch), nil when `error` is
    /// not a factor problem.
    static func describe(_ error: Error, slot: Int = defaultSlot) -> String?? {
        switch error {
        case let e as YubiKeyError: return .some(yubiKeyMessage(e, slot: slot))
        case let e as FactorError: return .some(factorMessage(e))
        case let e as FactorMessageError: return .some(e.message)
        case let e as KeyFileError: return .some(e.message)
        default: return nil
        }
    }

    // MARK: Key file

    /// A key file's bytes, at most `KeyFile.maxBytes` (Windows `read_keyfile`): only a regular file, read from one open
    /// handle. Blocking: callers run it off the main actor.
    static func readKeyFile(_ url: URL) throws -> Data {
        let name = url.lastPathComponent
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true else { throw keyFileUnreadable(name) }
        let data: Data
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            data = try handle.read(upToCount: KeyFile.maxBytes + 1) ?? Data()
        } catch {
            throw keyFileUnreadable(name)
        }
        guard data.count <= KeyFile.maxBytes else { throw keyFileTooLarge }
        return data
    }

    /// `readKeyFile` off the calling actor.
    static func loadKeyFile(_ url: URL) async throws -> Data {
        try await Task.detached(priority: .userInitiated) { try readKeyFile(url) }.value
    }

    @MainActor static func chooseKeyFile(message: String = chooseKeyFileTitle) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = message
        panel.prompt = String(localized: "Choose")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Where "Create key file" saves (KeePass's `.keyx` name, as Windows suggests).
    @MainActor static func chooseNewKeyFile() -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "LocalGateKeys.keyx"
        panel.canCreateDirectories = true
        panel.message = String(localized: "factors.createKeyFileTitle", defaultValue: "Create a key file")
        return panel.runModal() == .OK ? panel.url : nil
    }
}

/// "Create key file": a new KeePass XML 2.0 key file where the person chose (Windows `create_keyfile`): never in the
/// vault's folder, never over an existing file, owner-only (0600) from the moment it exists.
enum MacKeyFileWriter {
    static var notInVaultFolder: FactorMessageError {
        FactorMessageError(String(localized: "factors.keyFileNotInAppData",
                                  defaultValue: "Save the key file somewhere else than the LocalGateKeys data folder, for example on a USB stick."))
    }
    static func exists(_ name: String) -> FactorMessageError {
        FactorMessageError(String(localized: "factors.keyFileExists", defaultValue: "\(name) already exists. Choose a new file name."))
    }
    static var unwritable: FactorMessageError {
        FactorMessageError(String(localized: "factors.keyFileUnwritable", defaultValue: "The key file could not be saved there."))
    }

    static func write(_ content: Data, to url: URL, vaultDirectory: URL) throws {
        // Both through the same resolution of an existing folder (the new file does not exist yet).
        let target = url.standardizedFileURL.deletingLastPathComponent().resolvingSymlinksInPath().path
        let vault = vaultDirectory.standardizedFileURL.resolvingSymlinksInPath().path
        if target == vault || target.hasPrefix(vault.hasSuffix("/") ? vault : vault + "/") { throw notInVaultFolder }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let fd = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else {
            if errno == EEXIST { throw exists(url.lastPathComponent) }
            throw unwritable
        }
        var ok = true
        content.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while ok, offset < raw.count {
                let n = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if n <= 0 { ok = false } else { offset += n }
            }
        }
        if ok, fsync(fd) != 0 { ok = false }
        Darwin.close(fd)
        guard ok else {
            try? FileManager.default.removeItem(at: url)
            throw unwritable
        }
    }
}

/// A factor message shown as it is.
struct FactorMessageError: Error, Equatable, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
}

/// The key file remembered for this Mac's vault: an app-scoped, security-scoped bookmark (read only) in the app-only
/// Keychain group, with the factor's `check` it belongs to (a bookmark from an earlier vault or key file is ignored)
/// and the file name, for display. The key file itself is never copied into app storage.
struct KeyFileBookmark: Equatable, Sendable {
    let bookmark: [UInt8]
    let name: String
    let check: String

    static let createOptions: URL.BookmarkCreationOptions = [.withSecurityScope, .securityScopeAllowOnlyReadAccess]
    static let resolveOptions: URL.BookmarkResolutionOptions = [.withSecurityScope]

    func encoded() throws -> [UInt8] {
        try CanonicalJSON.encode(.object(["v": .int(1), "bookmark": .string(Base64.encode(bookmark)), "name": .string(name),
                                          "check": .string(check)]), dialect: .utf8)
    }

    init(bookmark: [UInt8], name: String, check: String) { self.bookmark = bookmark; self.name = name; self.check = check }

    init?(encoded: [UInt8]) {
        guard case .object(let o)? = try? CanonicalJSON.parse(encoded), o["v"] == .int(1),
              case .string(let b)? = o["bookmark"], let bytes = try? Base64.decodeStrict(b), !bytes.isEmpty,
              case .string(let name)? = o["name"], case .string(let check)? = o["check"] else { return nil }
        self.init(bookmark: bytes, name: name, check: check)
    }

    /// The stored bookmark when it belongs to the key file whose factor check is `check`.
    static func load(for check: String, from keychain: any KeychainVault) -> KeyFileBookmark? {
        guard let bytes = try? keychain.read(.unlockKeyFile), let mark = KeyFileBookmark(encoded: bytes), mark.check == check else { return nil }
        return mark
    }

    /// Remembers `url` (a file the person just picked, its grant still open) for the key file with `check`.
    static func save(_ url: URL, check: String, to keychain: any KeychainVault) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let bytes = Array(try url.bookmarkData(options: createOptions, includingResourceValuesForKeys: nil, relativeTo: nil))
        try keychain.write(.unlockKeyFile, try KeyFileBookmark(bookmark: bytes, name: url.lastPathComponent, check: check).encoded())
    }

    static func forget(in keychain: any KeychainVault) { try? keychain.delete(.unlockKeyFile) }

    /// The file now (a stale bookmark that still resolves is saved again); nil when it is gone.
    func resolve(keychain: any KeychainVault) -> URL? {
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: Data(bookmark), options: Self.resolveOptions, relativeTo: nil,
                                 bookmarkDataIsStale: &stale) else { return nil }
        if stale { try? Self.save(url, check: check, to: keychain) }
        return url
    }
}
