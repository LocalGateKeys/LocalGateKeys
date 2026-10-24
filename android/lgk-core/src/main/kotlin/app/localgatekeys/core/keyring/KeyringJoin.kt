package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.arr
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.obj
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock

internal object KeyringJoin {
    /**
     * [ring] (authenticated under [gk]) plus [identity] and its wrap; `prev_mac` carried over.
     * Written as format 2: the new entry lists this device's signing key and proof, a format-1
     * member gets null `signing_public` / `signing_proof`. Draws the device wrap (eph 32, nonce 12),
     * then the name nonce (12); the proof (Ed25519) draws nothing.
     */
    private fun withMember(
        ring: JsonValue,
        gk: GroupKey,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
    ): JsonValue {
        val addedAt = now.now
        if (addedAt < 0 || addedAt > Keyring.MAX_INT) throw KeyringException("bad-fields", "added_at")
        val body = LinkedHashMap(obj(ring))
        val wrap = Keyring.wrapDevice(gk, identity.deviceId, identity.exchangePublicKey, random)
        val exchange = Base64Std.encode(identity.exchangePublicKey)
        val signing = Base64Std.encode(identity.signingPublicKey)
        val proof = identity.sign(Keyring.proofMessage(gk.groupId, identity.deviceId, exchange, signing))
        val entry = JsonValue.Obj(
            mapOf(
                "device_id" to JsonValue.Str(identity.deviceId),
                "name_ct" to JsonValue.Str(MemberNames.sealName(gk, identity.deviceId, name, random)),
                "exchange_public" to JsonValue.Str(exchange),
                "signing_public" to JsonValue.Str(signing),
                "signing_proof" to JsonValue.Str(Base64Std.encode(proof)),
                "added_at" to JsonValue.Int(addedAt),
            ),
        )
        body["format"] = JsonValue.Int(Keyring.FORMAT) // a format-1 keyring is written back as format 2
        body["members"] = JsonValue.Arr(arr(body["members"]).map(::asFormat2) + entry)
        val wraps = LinkedHashMap(obj(body["device_wraps"]))
        wraps[identity.deviceId] = wrap
        body["device_wraps"] = JsonValue.Obj(wraps)
        return Keyring.finish(body, gk)
    }

    /** A member entry in format 2 (a format-1 entry gets null `signing_public` and `signing_proof`). */
    private fun asFormat2(member: JsonValue): JsonValue {
        val m = LinkedHashMap(obj(member))
        if ("signing_public" !in m) m["signing_public"] = JsonValue.Null
        if ("signing_proof" !in m) m["signing_proof"] = JsonValue.Null
        return JsonValue.Obj(m)
    }

    private fun checkIdentity(identity: DeviceIdentity) {
        if (!Identifier.isValid(identity.deviceId)) {
            throw KeyringException("bad-device-id", "device id must be ASCII [A-Za-z0-9._:-], 1..128 chars")
        }
    }

    /** The password key is derived only after the cheap checks. */
    fun join(
        ring: JsonValue,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
        passwordKey: () -> ByteArray,
    ): Pair<JsonValue, GroupKey> {
        KeyringParse.verifyStructure(ring)
        checkIdentity(identity)
        MemberNames.checkName(name)
        val members = arr(obj(ring)["members"])
        if (members.any { str(obj(it)["device_id"]) == identity.deviceId }) {
            throw KeyringException("already-member", "device is already a member")
        }
        if (members.size >= Keyring.MAX_MEMBERS) throw KeyringException("too-many-members", "the group already has 16 devices")
        val gk = Keyring.unwrap(ring, passwordKey())
        if (!Keyring.macOk(ring, gk)) throw KeyringException("tampered", "keyring MAC does not verify under the group key")
        return Pair(withMember(ring, gk, identity, name, random, now), gk)
    }

    fun attach(
        ring: JsonValue,
        identity: DeviceIdentity,
        name: String,
        stored: GroupKey,
        random: RandomSource,
        now: UnixClock,
        passwordKey: () -> ByteArray,
    ): JsonValue {
        KeyringParse.verifyStructure(ring)
        checkIdentity(identity)
        MemberNames.checkName(name)
        val o = obj(ring)
        if (str(o["group_id"]) != stored.groupId) {
            throw KeyringException("different-group-key", "the folder holds another sync group")
        }
        if (int(o["epoch"]) != stored.epoch) {
            throw KeyringException("epoch-mismatch", "the folder's group key is from another epoch")
        }
        val members = arr(o["members"]).map { obj(it) }
        val listed = members.any { str(it["device_id"]) == identity.deviceId }
        val ownKey = Base64Std.encode(identity.exchangePublicKey)
        if (listed && !members.any { str(it["device_id"]) == identity.deviceId && str(it["exchange_public"]) == ownKey }) {
            throw KeyringException("already-member", "another device is listed under this device id")
        }
        if (!listed && members.size >= Keyring.MAX_MEMBERS) {
            throw KeyringException("too-many-members", "the group already has 16 devices")
        }
        val gk = Keyring.unwrap(ring, passwordKey())
        if (!Keyring.constantTimeEqual(gk.key, stored.key)) {
            throw KeyringException("different-group-key", "the password opens a different group key")
        }
        if (!Keyring.macOk(ring, gk)) throw KeyringException("tampered", "keyring MAC does not verify under the group key")
        if (listed) {
            val own = try {
                Keyring.unwrapDevice(ring, identity)
            } catch (e: Exception) {
                null
            }
            if (own == null || !Keyring.constantTimeEqual(own.key, stored.key)) {
                throw KeyringException("already-member", "device is already a member")
            }
            return ring
        }
        return withMember(ring, gk, identity, name, random, now)
    }
}
