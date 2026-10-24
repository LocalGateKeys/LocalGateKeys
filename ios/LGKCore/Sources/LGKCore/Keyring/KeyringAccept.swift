extension Keyring {
    /// Authenticate `ring` against the device's trusted `(group_id, epoch, G)` (desktop `accept_keyring`).
    /// Returns the trusted key (same epoch) or the new key (epoch + 1). Reasons in order:
    /// structural, `group-mismatch`, `rollback`, `missed-rotation`, `tampered` (same epoch);
    /// then `not-member`, `key-mismatch`, `device-wrap`, `tampered` (chain, then MAC).
    public static func accept(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity) throws -> GroupKey {
        try verifyStructure(ring)
        let o = obj(ring)
        guard str(o["group_id"]) == trusted.groupID else { throw KeyringError("group-mismatch", "keyring belongs to another group") }
        let epoch = int(o["epoch"])!
        if epoch < trusted.epoch { throw KeyringError("rollback", "keyring is older than the trusted epoch") }
        if epoch > trusted.epoch + 1 { throw KeyringError("missed-rotation", "rejoin with the sync password") }
        if epoch == trusted.epoch {
            guard macOK(ring, key: trusted) else { throw KeyringError("tampered", "keyring MAC does not verify") }
            return trusted
        }
        let newKey = try unwrapDevice(ring, identity: identity)
        guard chainOK(o["prev_mac"], old: trusted, new: newKey) else {
            throw KeyringError("tampered", "keyring does not chain from the trusted epoch")
        }
        guard macOK(ring, key: newKey) else {
            throw KeyringError("tampered", "keyring MAC does not verify under the new group key")
        }
        return newKey
    }
}
