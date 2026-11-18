import Foundation
import AppShared

// Key file and YubiKey factors of the iPhone app password (docs/formats/COMPOSITE_KEY_V1.md, design §4.6/§4.7;
// Mac `MacFactors`, Android `AndroidFactorSource`): the messages, the bounded key-file read and the per-vault
// key-file bookmark. The YubiKey itself is `YubiKeyNFC.swift`. Factor problems happen before any key derivation, so
// the app-password throttle never counts them.

/// A factor message shown as it is.
struct FactorMessageError: Error, Equatable, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
}

/// The key file this iPhone remembers for the app password: its name (for display) and where it is now.
struct RememberedKeyFile: Equatable, Sendable {
    let name: String
    let url: URL
}

/// Where the lock model and Settings get the factors. The app's is `LivePhoneFactorSource`; tests use a fake.
@MainActor
protocol PhoneFactorSourcing: AnyObject {
    /// The key file remembered for the factor whose check is `check` (a bookmark of another key file is ignored).
    func rememberedKeyFile(check: String) -> RememberedKeyFile?
    /// The bytes of `url`, at most `KeyFile.maxBytes`, read off the main actor.
    func readKeyFile(_ url: URL) async throws -> Data
    /// Remembers `url` (picked this session) for the factor `check`; only after a successful unlock or change.
    func rememberKeyFile(_ url: URL, check: String)
    func forgetKeyFile()
    /// The YubiKey responder for `slot` (one NFC tap per answer); `confirming` asks twice and compares (enrolment).
    func yubiKey(slot: Int, confirming: Bool) -> @Sendable (Data) async throws -> Data
    /// Ends a waiting YubiKey exchange (Cancel, lock).
    func cancelYubiKey()
}

enum PhoneFactors {
    static let defaultSlot = 2

    /// Constant-time equality of two YubiKey answers.
    static func sameBytes(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    // MARK: Messages (Windows factors.*, vault.err.*; the Mac's keys where the text is the same)

    static var chooseKeyFileButton: String { String(localized: "factors.prompt.choose", defaultValue: "Choose key file…") }
    static var noKeyFileChosen: String { String(localized: "factors.prompt.noneChosen", defaultValue: "No key file chosen") }
    static func keyFileChosen(_ name: String) -> String { String(localized: "factors.prompt.chosen", defaultValue: "Key file: \(name)") }
    static var dontRemember: String { String(localized: "factors.phone.dontRemember", defaultValue: "Don't remember this key file") }
    static func yubiKeyNeeded(slot: Int) -> String {
        let s = String(slot)
        return DeviceText.isPad ? String(localized: "ipad.factors.yubikeyNeeded", defaultValue: "Hold your YubiKey (slot \(s)) to the top of your iPad when asked.") : String(localized: "factors.phone.yubikeyNeeded", defaultValue: "Hold your YubiKey (slot \(s)) to the top of your iPhone when asked.")
    }
    static var factorsRemovedByPhrase: String { String(localized: "recovery.factorsRemoved", defaultValue: "Key file / YubiKey removed; add them again.") }
    static var needsAppPassword: String {
        String(localized: "factors.phone.needsAppPassword", defaultValue: "Turn on the app password to add a key file or YubiKey")
    }
    static var openAppForFactors: String {
        String(localized: "autofill.factorsNeedApp", defaultValue: "Open LocalGateKeys to unlock this vault (it needs a key file or YubiKey).")
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

    // Settings › App password › Key file and YubiKey (the Mac's keys where the words are the same).
    static var section: String { String(localized: "factors.page.section", defaultValue: "Key file and YubiKey") }
    static var keyFile: String { String(localized: "factors.keyFile", defaultValue: "Key file") }
    static var yubiKey: String { String(localized: "factors.yubikey", defaultValue: "YubiKey") }
    static var keyFileOn: String { String(localized: "factors.phone.keyFileOn", defaultValue: "Set: needed with the app password") }
    static func yubiKeyOn(slot: Int) -> String {
        let s = String(slot)
        return String(localized: "factors.phone.yubikeyOn", defaultValue: "Set (slot \(s)): needed with the app password")
    }
    static var addKeyFile: String { String(localized: "factors.page.addKeyFile", defaultValue: "Add key file…") }
    static var addYubiKey: String { String(localized: "factors.page.addYubikey", defaultValue: "Add YubiKey") }
    static var removeKeyFileTitle: String { String(localized: "factors.removeKeyFileTitle", defaultValue: "Remove the key file") }
    static var removeYubiKeyTitle: String { String(localized: "factors.removeYubikeyTitle", defaultValue: "Remove the YubiKey") }
    static var addKeyFileTitle: String { String(localized: "factors.addKeyFileTitle", defaultValue: "Add a key file") }
    static var addYubiKeyTitle: String { String(localized: "factors.addYubikeyTitle", defaultValue: "Add a YubiKey") }
    static var hint: String {
        String(localized: "factors.phone.addHint",
               defaultValue: "A key file or YubiKey is then needed together with the app password to unlock LocalGateKeys. The recovery phrase still opens it without them.")
    }
    static var yubiKeySetup: String {
        String(localized: "factors.yubikeySetup",
               defaultValue: "LocalGateKeys never programs your YubiKey. Set it up in Yubico Authenticator: Slots, Challenge-response, HMAC-SHA1, slot 2 (or slot 1). A backup YubiKey needs the same secret.")
    }
    static var addConfirm: String {
        String(localized: "factors.phone.addConfirm",
               defaultValue: "From now on LocalGateKeys needs the app password and this factor to unlock. The recovery phrase still opens it without the factor.")
    }
    static var removeConfirm: String { String(localized: "factors.removeConfirm", defaultValue: "After this, the vault no longer needs this factor to unlock.") }
    static var alwaysAskTitle: String { String(localized: "factors.alwaysAskTitle", defaultValue: "Always ask for the key file / YubiKey") }
    static var alwaysAskNote: String {
        String(localized: "factors.phone.alwaysAskNote", defaultValue: "Turns off Face ID unlock while a key file or YubiKey is set.")
    }
    static var alwaysAskNeedsFactor: String { String(localized: "factors.alwaysAskNeedsFactor", defaultValue: "Add a key file or YubiKey first.") }
    static var faceIDOff: String {
        String(localized: "factors.phone.faceIDOff",
               defaultValue: "Face ID is off while \u{201C}Always ask for the key file / YubiKey\u{201D} is on.")
    }
    static func keyFileAdded(_ name: String) -> String { String(localized: "factors.keyFileAdded", defaultValue: "Key file \(name) added.") }
    static func yubiKeyAdded(slot: Int) -> String {
        let s = String(slot)
        return String(localized: "factors.yubikeyAdded", defaultValue: "YubiKey added (slot \(s)).")
    }
    static var keyFileRemoved: String { String(localized: "factors.keyFileRemoved", defaultValue: "Key file removed.") }
    static var yubiKeyRemoved: String { String(localized: "factors.yubikeyRemoved", defaultValue: "YubiKey removed.") }

    static func yubiKeyMessage(_ error: YubiKeyNFCError) -> String? {
        switch error {
        case .notAvailable:
            return DeviceText.isPad ? String(localized: "ipad.factors.nfcUnavailable", defaultValue: "This iPad can't read a YubiKey over NFC.") : String(localized: "factors.phone.nfcUnavailable", defaultValue: "This iPhone can't read a YubiKey over NFC.")
        case .tagLost:
            return String(localized: "factors.phone.tagLost", defaultValue: "Hold your YubiKey to the phone again.")
        case .timeout:
            return DeviceText.isPad ? String(localized: "ipad.factors.nfcTimeout", defaultValue: "No YubiKey found. Hold it to the top of your iPad and try again.") : String(localized: "factors.phone.nfcTimeout", defaultValue: "No YubiKey found. Hold it to the top of your iPhone and try again.")
        case .slotNotConfigured(let slot):
            let s = String(slot)
            return String(localized: "factors.yubikey.slotNotConfigured",
                          defaultValue: "Slot \(s) of this YubiKey is not set up for challenge-response. In Yubico Authenticator, choose Slots, then set slot \(s) to Challenge-response (HMAC-SHA1).")
        case .cancelled:
            return nil   // the person's own choice: nothing to say
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

    /// What to say about a factor problem.
    enum Description: Equatable {
        case message(String)
        /// A cancelled tap: nothing to say.
        case silent

        var text: String? {
            if case .message(let text) = self { return text }
            return nil
        }
    }

    /// The description of a factor problem, nil when `error` is not one.
    static func describe(_ error: Error) -> Description? {
        let text: String?
        switch error {
        case let e as YubiKeyNFCError: text = yubiKeyMessage(e)
        case let e as FactorError: text = factorMessage(e)
        case let e as FactorMessageError: text = e.message
        case let e as KeyFileError: text = e.message
        default: return nil
        }
        return text.map(Description.message) ?? .silent
    }

    // MARK: Key file

    /// A key file's bytes, at most `KeyFile.maxBytes` (Windows `read_keyfile`): only a regular file, read from one open
    /// handle, inside the picker's security scope; never copied into the app's storage. Blocking: callers run it off
    /// the main actor.
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
}

/// The key file remembered for this iPhone's app password: a document-picker bookmark (iOS has no app-scoped
/// security-scoped bookmarks; a bookmark made inside the picker's scope reopens it), in the app-only Keychain group,
/// with the factor's `check` it belongs to and the file name. The key file itself is never copied into the app.
struct PhoneKeyFileBookmark: Equatable, Sendable {
    let bookmark: [UInt8]
    let name: String
    let check: String

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

    static func load(for check: String, from keychain: any KeychainVault) -> PhoneKeyFileBookmark? {
        guard let bytes = try? keychain.read(.unlockKeyFile), let mark = PhoneKeyFileBookmark(encoded: bytes), mark.check == check else { return nil }
        return mark
    }

    /// Remembers `url` (a file the person picked, its scope still usable) for the key file with `check`.
    static func save(_ url: URL, check: String, to keychain: any KeychainVault) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let bytes = Array(try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil))
        try keychain.write(.unlockKeyFile, try PhoneKeyFileBookmark(bookmark: bytes, name: url.lastPathComponent, check: check).encoded())
    }

    static func forget(in keychain: any KeychainVault) { try? keychain.delete(.unlockKeyFile) }

    /// The file now (a stale bookmark that still resolves is saved again); nil when it is gone.
    func resolve(keychain: any KeychainVault) -> URL? {
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: Data(bookmark), options: [], relativeTo: nil,
                                 bookmarkDataIsStale: &stale) else { return nil }
        if stale { try? Self.save(url, check: check, to: keychain) }
        return url
    }
}
