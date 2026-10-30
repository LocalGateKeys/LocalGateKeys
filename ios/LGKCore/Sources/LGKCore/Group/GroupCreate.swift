/// Starting a sync group on this device.
public enum SyncGroup {
    /// A random uuid4 (lowercase, hyphenated), as `str(uuid.uuid4())`. Draws 16 bytes.
    static func uuid4(random: RandomSource) throws -> String {
        var u = random.bytes(count: 16)
        guard u.count == 16 else { throw KeyringError("bad-random", "random source must return exactly 16 bytes") }
        u[6] = (u[6] & 0x0F) | 0x40; u[8] = (u[8] & 0x3F) | 0x80
        let c = Array(lowerHex(u))
        return String(c[0..<8]) + "-" + String(c[8..<12]) + "-" + String(c[12..<16]) + "-" + String(c[16..<20]) + "-"
            + String(c[20..<32])
    }

    /// A new Wi-Fi-only group with this device as its only member (desktop `lan_sync.create_lan_group`): a fresh
    /// identity, a uuid4 group id, a random 32-byte key at epoch 1 and no cloud folder. The caller stores it
    /// (refusing when the vault is already in a group, `already-joined`).
    public static func createWiFi(installID: String, random: RandomSource) throws -> SyncGroupState {
        guard !installID.isEmpty, installID.unicodeScalars.count <= FolderSync.maxInstallID, !installID.contains("\u{0}") else {
            throw FolderSyncError("bad-install-id", "install id must be a non-empty bounded string")
        }
        let identity = try DeviceIdentity.generate(random: random)
        let groupID = try uuid4(random: random)
        let key = random.bytes(count: 32)
        let gk = try Keyring.groupKey(groupID, 1, key)
        return SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity, installID: installID,
                              hasFolder: false)
    }
}
