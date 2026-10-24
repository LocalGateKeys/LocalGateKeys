import Crypto

/// A refused or malformed pairing step (desktop `sync.pairing.PairingError` family).
public enum PairingError: Error, Equatable, Sendable {
    case malformed(String)
    case expired
    case authentication(String)
    /// The inviter answered with a refusal; the reason is one of `Enrollment.refusalReasons`.
    case refused(String)
}

/// Pairing canonical JSON: sorted keys, compact, `ensure_ascii=True`, at most 64 KiB.
enum Pairing {
    static let maxTranscriptBytes = 64 * 1024
    static let maxInt53: Int64 = (1 << 53) - 1

    static func canonical(_ v: JSONValue) throws -> [UInt8] {
        guard let data = try? CanonicalJSON.encode(v, dialect: .ascii) else {
            throw PairingError.malformed("Pairing transcript is not serializable")
        }
        guard data.count <= maxTranscriptBytes else { throw PairingError.malformed("Pairing transcript is too large") }
        return data
    }

    /// `base64.b64decode(validate=True)` plus an exact length (the desktop does not require the
    /// canonical re-encode here, but every value it writes is canonical).
    static func b64(_ v: JSONValue?, length: Int, _ field: String) throws -> [UInt8] {
        guard case .string(let s)? = v, let raw = try? Base64.decodeStrict(s) else {
            throw PairingError.malformed("\(field) is malformed")
        }
        guard raw.count == length else { throw PairingError.malformed("\(field) has an invalid length") }
        return raw
    }

    static func ident(_ v: JSONValue?, _ field: String) throws -> String {
        guard case .string(let s)? = v, Identifier.isValid(s) else { throw PairingError.malformed("\(field) is malformed") }
        return s
    }

    /// `_text`: non-empty string of at most `limit` code points without NUL.
    static func text(_ v: JSONValue?, _ field: String, limit: Int) throws -> String {
        guard case .string(let s)? = v, !s.isEmpty, s.unicodeScalars.count <= limit, !s.unicodeScalars.contains("\u{0}") else {
            throw PairingError.malformed("\(field) is malformed")
        }
        return s
    }

    /// `_private_lan_endpoint`: a literal LAN address (normalised like Python `str(ip_address)`) and a port.
    static func endpoint(host: JSONValue?, port: JSONValue?) throws -> LanEndpoint {
        guard case .string(let h)? = host, h.utf8.count <= 255 else { throw PairingError.malformed("Pairing endpoint host is malformed") }
        guard let norm = LanAddress.normalisedLAN(h) else { throw PairingError.malformed("Pairing endpoint must be a private LAN address") }
        guard case .int(let p)? = port, (1...65535).contains(p) else { throw PairingError.malformed("Pairing endpoint port is malformed") }
        return LanEndpoint(host: norm, port: Int(p))
    }

    static func strictJSON(_ data: [UInt8]) throws -> JSONValue {
        guard let v = try? CanonicalJSON.parse(data) else { throw PairingError.malformed("Enrollment message is malformed") }
        return v
    }
}

/// A literal LAN endpoint (host normalised).
public struct LanEndpoint: Equatable, Sendable {
    public let host: String
    public let port: Int

    /// Validates like the desktop `LANEndpoint` / `_private_lan_endpoint`.
    public init(validating host: String, port: Int) throws {
        self = try Pairing.endpoint(host: .string(host), port: .int(Int64(port)))
    }

    init(host: String, port: Int) { self.host = host; self.port = port }

    var json: JSONValue { .object(["host": .string(host), "port": .int(Int64(port))]) }
}

/// The scanned out-of-band enrollment bundle (desktop `PairingOffer`).
public struct PairingOffer: Equatable, Sendable {
    public static let qrPrefix = "lgk-pair:"
    public static let maxQRPayload = 1200

    public let version: Int64
    public let offerID: String
    public let groupID: String
    public let endpoint: LanEndpoint
    public let inviterDeviceID: String
    public let inviterSigningPublic: [UInt8]
    public let inviterExchangePublic: [UInt8]
    public let certificateFingerprint: String
    public let expiresAt: Int64
    public let transcriptNonce: [UInt8]
    public let pairingSecret: [UInt8]
    public let code: String

    /// Strict QR text parse (desktop `parse_qr_payload` + `from_bundle_dict`): prefix, unpadded
    /// canonical base64url, duplicate-free canonical JSON; unknown bundle keys are ignored.
    public static func parseQR(_ text: String) throws -> PairingOffer {
        guard text.unicodeScalars.count <= maxQRPayload, text.hasPrefix(qrPrefix) else {
            throw PairingError.malformed("Not a LocalGateKeys pairing code")
        }
        let body = String(text.dropFirst(qrPrefix.count))
        guard !body.isEmpty, body.utf8.count % 4 != 1, let raw = try? Base64URL.decodeNoPadStrict(body) else {
            throw PairingError.malformed("Pairing QR payload is malformed")
        }
        guard let value = try? CanonicalJSON.parse(raw), case .object = value else {
            throw PairingError.malformed("Pairing QR payload is malformed")
        }
        guard try Pairing.canonical(value) == raw else { throw PairingError.malformed("Pairing QR payload is not canonical") }
        return try fromBundle(value)
    }

    /// `PairingOffer.from_bundle_dict` plus `__post_init__`.
    public static func fromBundle(_ value: JSONValue) throws -> PairingOffer {
        guard case .object(let o) = value else { throw PairingError.malformed("Pairing offer is malformed") }
        guard case .object(let ep)? = o["endpoint"] else { throw PairingError.malformed("Pairing endpoint is malformed") }
        let endpoint = try Pairing.endpoint(host: ep["host"], port: ep["port"])
        let offerID = try Pairing.ident(o["offer_id"], "offer id")
        let groupID = try Pairing.ident(o["group_id"], "group id")
        let inviter = try Pairing.ident(o["inviter_device_id"], "inviter device id")
        let signing = try Pairing.b64(o["inviter_signing_public"], length: 32, "inviter signing key")
        let exchange = try Pairing.b64(o["inviter_exchange_public"], length: 32, "inviter exchange key")
        let fingerprint = try Pairing.text(o["certificate_fingerprint"], "certificate fingerprint", limit: 64)
        let nonce = try Pairing.b64(o["transcript_nonce"], length: 32, "transcript nonce")
        let secret = try Pairing.b64(o["pairing_secret"], length: 32, "pairing secret")
        let code = try Pairing.text(o["code"], "pairing code", limit: 8)
        guard fingerprint.utf8.count == 64, fingerprint.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else {
            throw PairingError.malformed("Pairing certificate fingerprint is malformed")
        }
        guard case .int(let expires)? = o["expires_at"], expires > 0, expires <= Pairing.maxInt53 else {
            throw PairingError.malformed("Pairing expiration is malformed")
        }
        guard code.utf8.count == 8, code.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
            throw PairingError.malformed("Pairing code is malformed")
        }
        // The desktop defaults a missing version to 1 and copies any other value into the transcript;
        // here it must be an integer (anything else could not be re-serialised identically).
        let version: Int64
        switch o["version"] {
        case nil: version = 1
        case .int(let v)?: version = v
        default: throw PairingError.malformed("Pairing offer version is malformed")
        }
        return PairingOffer(version: version, offerID: offerID, groupID: groupID, endpoint: endpoint,
                            inviterDeviceID: inviter, inviterSigningPublic: signing, inviterExchangePublic: exchange,
                            certificateFingerprint: fingerprint, expiresAt: expires, transcriptNonce: nonce,
                            pairingSecret: secret, code: code)
    }

    /// The reviewable bundle without the two enrollment credentials.
    public var publicJSON: JSONValue {
        .object([
            "version": .int(version), "offer_id": .string(offerID), "group_id": .string(groupID),
            "endpoint": endpoint.json, "inviter_device_id": .string(inviterDeviceID),
            "inviter_signing_public": .string(Base64.encode(inviterSigningPublic)),
            "inviter_exchange_public": .string(Base64.encode(inviterExchangePublic)),
            "certificate_fingerprint": .string(certificateFingerprint), "expires_at": .int(expiresAt),
            "transcript_nonce": .string(Base64.encode(transcriptNonce)),
        ])
    }

    public var bundleJSON: JSONValue {
        guard case .object(var o) = publicJSON else { return publicJSON }
        o["pairing_secret"] = .string(Base64.encode(pairingSecret))
        o["code"] = .string(code)
        return .object(o)
    }

    /// The inviter as the pinned LAN peer the new device stores after a successful enrollment.
    public var inviterPeer: PinnedPeer {
        PinnedPeer(deviceID: inviterDeviceID, groupID: groupID, signingPublic: inviterSigningPublic,
                   exchangePublic: inviterExchangePublic, endpoint: endpoint)
    }

    /// `_check_offer`: not expired at `now` and the fingerprint matches the pinned signing key.
    func check(now: Int64) throws {
        if now < 0 { throw PairingError.malformed("Pairing clock value is malformed") }
        if now >= expiresAt { throw PairingError.expired }
        if lowerHex(Array(SHA256.hash(data: inviterSigningPublic))) != certificateFingerprint {
            throw PairingError.authentication("Pairing certificate fingerprint does not match the pinned key")
        }
    }
}
