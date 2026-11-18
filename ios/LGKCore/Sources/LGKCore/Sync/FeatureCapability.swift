/// Folder capability files (desktop `attachment_flow`; Kotlin `FeatureCapability`): a signed, zero-record, format-1
/// view of the current epoch in `LocalGateKeys Sync/attachments/`, one per feature, telling the other members what this
/// device reads. The view counter tells the features apart, so a file copied under the other name never counts:
///
/// - documents: `<device>.lgkcap` (+ `.lgkcap.lgksig`), counter 0;
/// - personal collections (sub-plan 07 Task 4): `<device>.lgkcol` (+ `.lgkcol.lgksig`), counter 1;
/// - the emergency access plan (sub-plan 08): `<device>.lgkheircap` (+ `.lgkheircap.lgksig`), counter
///   `FolderBlobs.heirCapCounter`.
///
/// Vectors: `tests/vectors/share/collections/capability.json`. `FolderSync` with `collections` writes this device's
/// `.lgkcol` file (`FolderBlobs.writeCapability(feature:)`) and checks every other member's.
public enum FeatureCapability {
    public enum Feature: Sendable, CaseIterable {
        case documents, collections, heir

        public var suffix: String {
            switch self {
            case .documents: FolderBlobs.capSuffix
            case .collections: ".lgkcol"
            case .heir: FolderBlobs.heirCapSuffix
            }
        }

        public var signatureSuffix: String {
            switch self {
            case .documents: FolderBlobs.capSigSuffix
            case .collections: ".lgkcol.lgksig"
            case .heir: FolderBlobs.heirCapSigSuffix
            }
        }

        public var counter: Int64 {
            switch self {
            case .documents: 0
            case .collections: 1
            case .heir: FolderBlobs.heirCapCounter
            }
        }
    }

    /// Whether `raw` (with signature `sig`) is `deviceID`'s capability file for `feature` under `gk`, signed by
    /// `signer` (base64 Ed25519; nil never counts). Anything malformed is simply "not capable".
    public static func verify(_ raw: [UInt8]?, sig: [UInt8]?, key gk: GroupKey, deviceID: String, signer: String?,
                              feature: Feature) -> Bool {
        guard let raw, let sig, let signer, raw.count <= FolderBlobs.maxCapBytes, sig.count <= ViewSignature.maxBytes,
              let view = try? ViewFile.decode(raw, key: gk, expectedDeviceID: deviceID, maxBytes: FolderBlobs.maxCapBytes,
                                              maxRecords: 0),
              view.header.counter == feature.counter,
              let key = try? ViewSignature.verify(sig, raw: raw, header: view.header) else { return false }
        return Array(Base64.encode(key).utf8) == Array(signer.utf8)
    }

    /// The capability file and its signature for `identity` under `gk`.
    public static func encode(key gk: GroupKey, identity: DeviceIdentity, feature: Feature, clock: some UnixClock,
                              random: some RandomSource) throws -> (file: [UInt8], sig: [UInt8]) {
        let raw = try ViewFile.encode(key: gk, deviceID: identity.deviceID, counter: feature.counter, states: [],
                                      now: clock, random: random)
        return (raw, try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: identity))
    }
}
