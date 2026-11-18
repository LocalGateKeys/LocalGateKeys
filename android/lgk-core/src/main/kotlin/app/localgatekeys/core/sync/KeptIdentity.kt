package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Identifier

/**
 * What Leave sync keeps of this device's membership, so joining the same group again shows this device under its old
 * id instead of as a second device (design 2026-11-17 keep-device-id-on-rejoin, rules 1-3).
 *
 * Besides the id, its keys and the group they belong to, it holds every counter of this device that a peer checks
 * before it accepts something from this id, so a rejoin continues them and is never taken for a replay or a rollback:
 * - [ownCounter]: the view counter of this device's own folder file. A peer refuses a file whose counter is below the
 *   last one it accepted from this id at that epoch (`rollback`), or the same counter with other bytes.
 * - [generationOffset]: part of this vault's generation (store revision + offset). A peer that witnessed a higher
 *   generation from this id warns of a rolled-back vault.
 * The hello counter is not here: it is this installation's own and Leave already keeps it. The key epoch is not kept:
 * a join always takes the group's current one, and peers clear what they hold per epoch when it changes.
 *
 * Local only: the app seals it with the vault's other sync secrets; it is never sent, synced, backed up or exported.
 * [encode] is that local form.
 */
class KeptIdentity(
    val groupId: String,
    val identity: DeviceIdentity,
    val ownCounter: Long,
    val generationOffset: Long,
) {
    init {
        if (!Identifier.isValid(groupId) || ownCounter < 0 || generationOffset < 0) throw IllegalArgumentException("bad kept identity")
    }

    val deviceId: String get() = identity.deviceId

    /**
     * A new group state of the same group joined with this identity, with this device's counters continued: never
     * below what was kept, never below what the join already set.
     */
    fun continuing(state: SyncGroupState): SyncGroupState {
        require(state.groupId == groupId && state.deviceId == deviceId) { "not this kept identity's group state" }
        return state.copy(
            ownCounter = maxOf(state.ownCounter, ownCounter),
            generationOffset = maxOf(state.generationOffset, generationOffset),
        )
    }

    /** The local stored form (canonical JSON; holds the private keys). */
    fun encode(): ByteArray = CanonicalJson.encode(
        JsonValue.Obj(
            mapOf(
                "format" to JsonValue.Int(FORMAT),
                "group_id" to JsonValue.Str(groupId),
                "device_id" to JsonValue.Str(identity.deviceId),
                "signing_private" to JsonValue.Str(Base64Std.encode(identity.signingPrivateKey)),
                "exchange_private" to JsonValue.Str(Base64Std.encode(identity.exchangePrivateKey)),
                "own_counter" to JsonValue.Int(ownCounter),
                "generation_offset" to JsonValue.Int(generationOffset),
            ),
        ),
        Dialect.UTF8,
    )

    /** Never shows the keys. */
    override fun toString(): String = "KeptIdentity(group=$groupId, device=${identity.deviceId}, ownCounter=$ownCounter)"

    companion object {
        const val FORMAT: Long = 1
        private val FIELDS = setOf(
            "format", "group_id", "device_id", "signing_private", "exchange_private", "own_counter", "generation_offset",
        )

        /** What Leave keeps of [state]. */
        fun of(state: SyncGroupState): KeptIdentity =
            KeptIdentity(state.groupId, state.identity, state.ownCounter, state.generationOffset)

        /** [encode]'s form back; anything else throws [IllegalArgumentException]. */
        fun decode(raw: ByteArray): KeptIdentity {
            val f = try {
                (CanonicalJson.parse(raw) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            }
            if (f == null || f.keys != FIELDS || f["format"] != JsonValue.Int(FORMAT)) throw IllegalArgumentException("bad kept identity")
            fun str(k: String) = (f[k] as? JsonValue.Str)?.v ?: throw IllegalArgumentException("bad kept identity")
            fun int(k: String) = (f[k] as? JsonValue.Int)?.v ?: throw IllegalArgumentException("bad kept identity")
            return try {
                val identity = DeviceIdentity(
                    str("device_id"), Base64Std.decodeStrict(str("signing_private")), Base64Std.decodeStrict(str("exchange_private")),
                )
                KeptIdentity(str("group_id"), identity, int("own_counter"), int("generation_offset"))
            } catch (e: IllegalArgumentException) {
                throw e
            } catch (e: Exception) {
                throw IllegalArgumentException("bad kept identity")
            }
        }
    }
}
