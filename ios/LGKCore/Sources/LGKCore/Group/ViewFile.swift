import Crypto

/// Parsed `LGKSYNC1` header line. Format 2 (rollback witnesses, 2026-10-29) adds `vaultGeneration` and
/// `witness`; they are nil / empty for a format-1 header.
public struct ViewHeader: Equatable, Sendable {
    public let format: Int64
    public let groupID: String
    public let deviceID: String
    public let epoch: Int64
    public let counter: Int64
    public let writtenAt: Int64
    /// The writer's vault generation (format 2), nil for format 1.
    public let vaultGeneration: Int64?
    /// The writer's witness of its peers (format 2), empty for format 1.
    public let witness: [String: Int64]

    public init(format: Int64, groupID: String, deviceID: String, epoch: Int64, counter: Int64, writtenAt: Int64,
                vaultGeneration: Int64? = nil, witness: [String: Int64] = [:]) {
        self.format = format; self.groupID = groupID; self.deviceID = deviceID
        self.epoch = epoch; self.counter = counter; self.writtenAt = writtenAt
        self.vaultGeneration = vaultGeneration; self.witness = witness
    }

    var json: JSONValue {
        var o: [String: JSONValue] = ["format": .int(format), "group_id": .string(groupID), "device_id": .string(deviceID),
                                      "epoch": .int(epoch), "counter": .int(counter), "written_at": .int(writtenAt)]
        if let vaultGeneration {
            o["vault_generation"] = .int(vaultGeneration)
            o["witness"] = .object(witness.mapValues { JSONValue.int($0) })
        }
        return .object(o)
    }
}

/// Device view files (desktop `sync.group.encode_view` / `decode_view`).
public enum ViewFile {
    public static let magic = Array("LGKSYNC1\n".utf8)
    public static let format: Int64 = 1
    /// View format 2: the header also carries `vault_generation` and `witness` (desktop `FORMAT_WITNESS`).
    public static let formatWitness: Int64 = 2
    /// At most this many witness entries (desktop `MAX_WITNESS`).
    public static let maxWitness = 64
    public static let maxBytes = 64 * 1024 * 1024
    public static let maxRecords = 20000
    private static let headerFields: Set<String> = ["format", "group_id", "device_id", "epoch", "counter", "written_at"]
    private static let headerFieldsV2: Set<String> = headerFields.union(["vault_generation", "witness"])

    /// Desktop `_check_witness_values`: a generation in 0..2**53-1, and at most 64 entries whose keys are valid
    /// ids other than the writer's own and whose values are in the same range.
    private static func checkWitnessValues(device: String, vaultGeneration: JSONValue?,
                                           witness: JSONValue?) throws -> [String: Int64] {
        guard SealedItem.isInt(vaultGeneration) else { throw SyncFormatError("bad-header", "invalid vault_generation") }
        guard case .object(let w)? = witness, w.count <= maxWitness else {
            throw SyncFormatError("bad-header", "invalid witness")
        }
        var out: [String: Int64] = [:]
        for (peer, value) in w {
            guard Identifier.isValid(peer), peer != device, SealedItem.isInt(value), case .int(let g) = value else {
                throw SyncFormatError("bad-header", "invalid witness entry")
            }
            out[peer] = g
        }
        return out
    }

    private static func checkHeaderValues(device: JSONValue?, epoch: JSONValue?, counter: JSONValue?, writtenAt: JSONValue?) throws {
        let validDevice: Bool
        if case .string(let d)? = device { validDevice = Identifier.isValid(d) } else { validDevice = false }
        if !validDevice || !SealedItem.isInt(counter) || !SealedItem.isInt(writtenAt) {
            throw SyncFormatError("bad-header", "invalid device_id/counter/written_at")
        }
        if !SealedItem.isInt(epoch) { throw SyncFormatError("bad-header", "invalid epoch") }
    }

    /// Serialises `states` (sorted by id) into one view file. Nonces: one per item in id order, then the file nonce.
    /// Format 1 unless `vaultGeneration` is given; then format 2 with `witness` (default empty).
    public static func encode(key: GroupKey, deviceID: String, counter: Int64, states: [ItemState],
                              now: some UnixClock, random: some RandomSource, maxRecords: Int = maxRecords,
                              vaultGeneration: Int64? = nil, witness: [String: Int64]? = nil) throws -> [UInt8] {
        let writtenAt = now.now
        try checkHeaderValues(device: .string(deviceID), epoch: .int(key.epoch), counter: .int(counter), writtenAt: .int(writtenAt))
        if vaultGeneration == nil && witness != nil {
            throw SyncFormatError("bad-header", "a witness needs a vault_generation")
        }
        var checkedWitness: [String: Int64] = [:]
        if let vaultGeneration {
            checkedWitness = try checkWitnessValues(device: deviceID, vaultGeneration: .int(vaultGeneration),
                                                    witness: .object((witness ?? [:]).mapValues { JSONValue.int($0) }))
        }
        // Ids are ASCII, so String order equals code point order.
        let ordered = states.sorted { $0.itemID < $1.itemID }
        if ordered.count > maxRecords { throw SyncFormatError("too-many-records", "\(ordered.count) > \(maxRecords)") }
        for (a, b) in zip(ordered, ordered.dropFirst()) where a.itemID == b.itemID {
            throw SyncFormatError("duplicate-id", a.itemID)
        }
        var used = Set<[UInt8]>()
        func uniqueNonce() throws -> [UInt8] {
            let n = try SealedItem.nonce(random)
            guard used.insert(n).inserted else { throw SyncFormatError("nonce-reuse", "nonce source repeated a nonce") }
            return n
        }
        var sealed: [JSONValue] = []
        sealed.reserveCapacity(ordered.count)
        for s in ordered { sealed.append(try SealedItem.seal(key, s, nonce: try uniqueNonce())) }
        let header = try CanonicalJSON.encode(
            ViewHeader(format: vaultGeneration == nil ? format : formatWitness, groupID: key.groupID,
                       deviceID: deviceID, epoch: key.epoch, counter: counter, writtenAt: writtenAt,
                       vaultGeneration: vaultGeneration, witness: checkedWitness).json, dialect: .utf8)
        let nonce = try uniqueNonce()
        let body = try CryptoBox.sealGCM(key: key.fileKey, nonce: nonce,
                                         plaintext: CanonicalJSON.encode(.array(sealed), dialect: .utf8), aad: header)
        return magic + header + [0x0A] + nonce + body
    }

    /// Parses, authenticates and opens a device view file.
    public static func decode(_ data: [UInt8], key: GroupKey, expectedDeviceID: String?,
                              maxBytes: Int = maxBytes, maxRecords: Int = maxRecords) throws -> (header: ViewHeader, states: [ItemState]) {
        if data.count > maxBytes { throw SyncFormatError("too-large", "\(data.count) > \(maxBytes)") }
        let (header, headerBytes, end) = try parseHeader(data)
        if header.groupID != key.groupID { throw SyncFormatError("group-mismatch", "view belongs to another group") }
        if header.epoch != key.epoch { throw SyncFormatError("epoch-mismatch", "view was written under another epoch") }
        if let expected = expectedDeviceID, header.deviceID != expected {
            throw SyncFormatError("device-mismatch", "view was written by another device")
        }
        return (header, try openPayload(data, key: key, headerBytes: headerBytes, end: end, maxRecords: maxRecords))
    }

    /// The header of a view file (structure checks only, nothing authenticated): for signing and tests.
    public static func decodeHeader(_ data: [UInt8]) throws -> ViewHeader { try parseHeader(data).0 }

    private static func parseHeader(_ data: [UInt8]) throws -> (ViewHeader, [UInt8], Int) {
        guard data.starts(with: magic) else { throw SyncFormatError("bad-magic", "not a LocalGateKeys sync view") }
        guard let end = data[magic.count...].firstIndex(of: 0x0A) else { throw SyncFormatError("bad-header", "missing header line") }
        let headerBytes = Array(data[magic.count..<end])
        guard let parsed = try? CanonicalJSON.parse(headerBytes) else { throw SyncFormatError("bad-header", "header is not JSON") }
        guard case .object(let h) = parsed, h["format"] != nil else { throw SyncFormatError("bad-header", "header fields") }
        guard case .int(let fmt)? = h["format"], fmt == format || fmt == formatWitness else {
            throw SyncFormatError("bad-header", "unsupported format")
        }
        guard Set(h.keys) == (fmt == format ? headerFields : headerFieldsV2) else {
            throw SyncFormatError("bad-header", "header fields")
        }
        guard case .string(let groupID)? = h["group_id"], Identifier.isValid(groupID) else {
            throw SyncFormatError("bad-header", "group_id")
        }
        try checkHeaderValues(device: h["device_id"], epoch: h["epoch"], counter: h["counter"], writtenAt: h["written_at"])
        var generation: Int64?
        var witness: [String: Int64] = [:]
        if fmt == formatWitness, case .string(let writer)? = h["device_id"] {
            witness = try checkWitnessValues(device: writer, vaultGeneration: h["vault_generation"], witness: h["witness"])
            if case .int(let g)? = h["vault_generation"] { generation = g }
        }
        guard let canonical = try? CanonicalJSON.encode(parsed, dialect: .utf8) else {
            throw SyncFormatError("bad-header", "header is not canonical-JSON safe")
        }
        if canonical != headerBytes { throw SyncFormatError("header-noncanonical", "header line is not canonical JSON") }
        guard case .string(let deviceID)? = h["device_id"], case .int(let epoch)? = h["epoch"],
              case .int(let counter)? = h["counter"], case .int(let writtenAt)? = h["written_at"] else {
            throw SyncFormatError("bad-header", "header fields")
        }
        let header = ViewHeader(format: fmt, groupID: groupID, deviceID: deviceID, epoch: epoch, counter: counter,
                                writtenAt: writtenAt, vaultGeneration: generation, witness: witness)
        return (header, headerBytes, end)
    }

    private static func openPayload(_ data: [UInt8], key: GroupKey, headerBytes: [UInt8], end: Int,
                                    maxRecords: Int) throws -> [ItemState] {
        let blob = data[(end + 1)...]
        if blob.count < SealedItem.nonceLength + SealedItem.tagLength { throw SyncFormatError("bad-payload", "payload too short") }
        let nonceEnd = blob.startIndex + SealedItem.nonceLength
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: key.fileKey, nonce: Array(blob[..<nonceEnd]),
                                          ciphertext: Array(blob[nonceEnd...]), aad: headerBytes)
        } catch { throw SyncFormatError("auth-failed", "view authentication failed") }
        guard let payload = try? CanonicalJSON.parse(plain) else { throw SyncFormatError("bad-payload", "payload is not JSON") }
        guard case .array(let records) = payload else { throw SyncFormatError("bad-payload", "payload must be a list") }
        if records.count > maxRecords { throw SyncFormatError("too-many-records", "\(records.count) > \(maxRecords)") }
        let recordKey = key.recordKey
        var states: [ItemState] = []
        states.reserveCapacity(records.count)
        var seen = Set<String>()
        for rec in records {
            guard case .object(let o) = rec else { throw SyncFormatError("bad-payload", "record must be an object") }
            if case .string(let rid)? = o["id"], !seen.insert(rid).inserted { throw SyncFormatError("duplicate-id", rid) }
            states.append(try SealedItem.open(key, rec, recordKey: recordKey))
        }
        return states
    }
}

/// View signature files (desktop `group.sign_view` / `verify_view_signature`, audit 2026-10-24 M-7; format in the
/// "View signature" block of `sync/group.py`). The view file itself is unchanged; the writer stores this next to it.
public enum ViewSignature {
    static let label = Array("lgk-sync-view-sig-v1|".utf8)
    public static let format: Int64 = 1
    public static let maxBytes = 4096
    private static let fields: Set<String> = ["format", "group_id", "device_id", "epoch", "counter", "view_sha256",
                                              "signing_public", "sig"]

    static func body(_ header: ViewHeader, raw: [UInt8], signingPublic: [UInt8]) -> [String: JSONValue] {
        ["format": .int(format), "group_id": .string(header.groupID), "device_id": .string(header.deviceID),
         "epoch": .int(header.epoch), "counter": .int(header.counter),
         "view_sha256": .string(lowerHex(SHA256.hash(data: raw))),
         "signing_public": .string(Base64.encode(signingPublic))]
    }

    /// The signature file for the view file `raw` (whose header is `header`), signed by `identity`.
    /// CryptoKit signs with hedged randomness, so the bytes differ from the desktop's; both verify everywhere.
    public static func sign(_ raw: [UInt8], header: ViewHeader, identity: DeviceIdentity) throws -> [UInt8] {
        let b = body(header, raw: raw, signingPublic: identity.signingPublicKey)
        let sig = try identity.sign(label + CanonicalJSON.encode(.object(b), dialect: .utf8))
        var signed = b
        signed["sig"] = .string(Base64.encode(sig))
        return try CanonicalJSON.encode(.object(signed), dialect: .utf8)
    }

    private static func b64(_ v: JSONValue?, length: Int) throws -> [UInt8] {
        guard case .string(let s)? = v, let out = try? Base64.decodeStrict(s), out.count == length else {
            throw SyncFormatError("sig-malformed", "base64 field")
        }
        return out
    }

    /// The raw Ed25519 key that validly signed `raw` (decoded header `header`); throws `SyncFormatError`
    /// `sig-malformed`, `sig-stale` or `sig-mismatch`. Which key is the right one is the transport's policy.
    public static func verify(_ sigRaw: [UInt8], raw: [UInt8], header: ViewHeader) throws -> [UInt8] {
        if sigRaw.count > maxBytes { throw SyncFormatError("sig-malformed", "signature file too large") }
        guard let parsed = try? CanonicalJSON.parse(sigRaw) else {
            throw SyncFormatError("sig-malformed", "signature file is not JSON")
        }
        guard case .object(let o) = parsed, Set(o.keys) == fields else {
            throw SyncFormatError("sig-malformed", "signature fields")
        }
        guard o["format"] == .int(format) else { throw SyncFormatError("sig-malformed", "unsupported signature format") }
        guard case .string(let groupID)? = o["group_id"], Identifier.isValid(groupID),
              case .string(let deviceID)? = o["device_id"], Identifier.isValid(deviceID),
              SealedItem.isInt(o["epoch"]), SealedItem.isInt(o["counter"]),
              case .int(let epoch)? = o["epoch"], case .int(let counter)? = o["counter"] else {
            throw SyncFormatError("sig-malformed", "signature header fields")
        }
        let hexDigits = Set("0123456789abcdef")
        guard case .string(let digest)? = o["view_sha256"], digest.count == 64, digest.allSatisfy({ hexDigits.contains($0) }) else {
            throw SyncFormatError("sig-malformed", "view_sha256")
        }
        let publicKey = try b64(o["signing_public"], length: 32)
        let sig = try b64(o["sig"], length: 64)
        guard let canonical = try? CanonicalJSON.encode(parsed, dialect: .utf8) else {
            throw SyncFormatError("sig-malformed", "signature file is not canonical-JSON safe")
        }
        if canonical != sigRaw { throw SyncFormatError("sig-malformed", "signature file is not canonical JSON") }
        if groupID != header.groupID || deviceID != header.deviceID || epoch != header.epoch || counter != header.counter {
            throw SyncFormatError("sig-stale", "the signature belongs to another write")
        }
        if digest != lowerHex(SHA256.hash(data: raw)) {
            throw SyncFormatError("sig-mismatch", "the view differs from the signed one")
        }
        var unsigned = o
        unsigned["sig"] = nil
        let message = label + (try CanonicalJSON.encode(.object(unsigned), dialect: .utf8))
        guard DeviceIdentity.verify(signature: sig, message: message, publicKey: publicKey) else {
            throw SyncFormatError("sig-mismatch", "the signature does not verify")
        }
        return publicKey
    }
}
