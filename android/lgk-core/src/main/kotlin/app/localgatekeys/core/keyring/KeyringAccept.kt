package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.obj
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.lan.DeviceIdentity

internal object KeyringAccept {
    /**
     * Authenticate [ring] against the device's trusted `(group_id, epoch, G)` (desktop `accept_keyring`).
     * Returns the trusted key (same epoch) or the new key (epoch + 1). Reasons in order:
     * structural, `group-mismatch`, `rollback`, `missed-rotation`, `tampered` (same epoch);
     * then `not-member`, `key-mismatch`, `device-wrap`, `tampered` (chain, then MAC).
     */
    fun accept(ring: JsonValue, trusted: GroupKey, identity: DeviceIdentity): GroupKey {
        KeyringParse.verifyStructure(ring)
        val o = obj(ring)
        if (str(o["group_id"]) != trusted.groupId) throw KeyringException("group-mismatch", "keyring belongs to another group")
        val epoch = int(o["epoch"])!!
        if (epoch < trusted.epoch) throw KeyringException("rollback", "keyring is older than the trusted epoch")
        if (epoch > trusted.epoch + 1) throw KeyringException("missed-rotation", "rejoin with the sync password")
        if (epoch == trusted.epoch) {
            if (!Keyring.macOk(ring, trusted)) throw KeyringException("tampered", "keyring MAC does not verify")
            return trusted
        }
        val newKey = Keyring.unwrapDevice(ring, identity)
        if (!Keyring.chainOk(o["prev_mac"], trusted, newKey)) {
            throw KeyringException("tampered", "keyring does not chain from the trusted epoch")
        }
        if (!Keyring.macOk(ring, newKey)) {
            throw KeyringException("tampered", "keyring MAC does not verify under the new group key")
        }
        return newKey
    }
}
