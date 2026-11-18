package app.localgatekeys.core.lan

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.SyncGroupState
import java.security.MessageDigest

/**
 * One LAN peer this device lists in its group state as a host (desktop `SyncGroupState.lan_peers` entry, Swift
 * `LanPeer`): `PairedDevice` + `endpoint` + `name`. A removed peer stays listed with [revoked] so its id can never come
 * back; its keys stay pinned so a hello of it is recognised and refused.
 */
class LanPeer(
    val deviceId: String,
    val groupId: String,
    /** The name the device gave when it enrolled (display only, not authenticated by a key). */
    val name: String? = null,
    /** Where the peer listens; null when it always initiates (a phone, or any peer of a phone host). */
    val endpoint: LanEndpoint? = null,
    signingPublic: ByteArray,
    exchangePublic: ByteArray,
    val pairedAt: Long = 0,
    val revoked: Boolean = false,
    /**
     * The downgrade pin of LAN protocol version 3 (stored `"hello":3`): the peer has used the sealed hello, so its
     * clear-text hello is refused. null: not pinned.
     */
    val hello: Long? = null,
    /** Stored fields this version does not know, kept as they are. */
    extras: Map<String, JsonValue> = emptyMap(),
) {
    private val signing = signingPublic.copyOf()
    private val exchange = exchangePublic.copyOf()
    /** A non-integer stored `hello` is kept here as it is (it is not a pin). */
    val extras: Map<String, JsonValue> = extras.filterKeys { it !in KNOWN_FIELDS || (it == "hello" && hello == null) }

    val signingPublic: ByteArray get() = signing.copyOf()
    val exchangePublic: ByteArray get() = exchange.copyOf()

    /** Pinned to the sealed hello (`hello` is at least 3). */
    val sealed: Boolean get() = (hello ?: 0) >= LanTransport.VERSION

    /** Lowercase hex SHA-256 of the signing key. */
    val fingerprint: String get() = Hex.lower(MessageDigest.getInstance("SHA-256").digest(signing))

    val pinned: PinnedPeer get() = PinnedPeer(deviceId, groupId, signing.copyOf(), exchange.copyOf(), endpoint)

    /** The stored form (the app's encrypted store; never sent). */
    val json: JsonValue
        get() {
            val o = LinkedHashMap<String, JsonValue>(extras)
            o["device_id"] = JsonValue.Str(deviceId)
            o["group_id"] = JsonValue.Str(groupId)
            o["name"] = name?.let { JsonValue.Str(it) } ?: JsonValue.Null
            o["endpoint"] = endpoint?.json ?: JsonValue.Null
            o["signing_public"] = JsonValue.Str(Base64Std.encode(signing))
            o["exchange_public"] = JsonValue.Str(Base64Std.encode(exchange))
            o["paired_at"] = JsonValue.Int(pairedAt)
            o["revoked"] = JsonValue.Bool(revoked)
            hello?.let { o["hello"] = JsonValue.Int(it) }
            return JsonValue.Obj(o)
        }

    fun copy(
        name: String? = this.name,
        endpoint: LanEndpoint? = this.endpoint,
        revoked: Boolean = this.revoked,
        hello: Long? = this.hello,
    ): LanPeer = LanPeer(deviceId, groupId, name, endpoint, signing, exchange, pairedAt, revoked, hello, extras)

    override fun equals(other: Any?): Boolean =
        other is LanPeer && deviceId == other.deviceId && groupId == other.groupId && name == other.name &&
            endpoint == other.endpoint && signing.contentEquals(other.signing) && exchange.contentEquals(other.exchange) &&
            pairedAt == other.pairedAt && revoked == other.revoked && hello == other.hello && extras == other.extras

    override fun hashCode(): Int = (deviceId.hashCode() * 31 + signing.contentHashCode()) * 31 + revoked.hashCode()

    /** Never shows the keys. */
    override fun toString(): String = "LanPeer(deviceId=$deviceId, revoked=$revoked, sealed=$sealed)"

    companion object {
        val KNOWN_FIELDS: Set<String> = setOf(
            "device_id", "group_id", "name", "endpoint", "signing_public", "exchange_public", "paired_at", "revoked", "hello",
        )

        private fun bad(detail: String) = LanSyncException("bad-peer", detail)

        /** The stored form back; anything malformed throws [LanSyncException] `bad-peer`. */
        fun fromJson(v: JsonValue): LanPeer {
            val o = (v as? JsonValue.Obj)?.fields ?: throw bad("stored LAN peer is malformed")
            val device = (o["device_id"] as? JsonValue.Str)?.v
            val group = (o["group_id"] as? JsonValue.Str)?.v
            val paired = (o["paired_at"] as? JsonValue.Int)?.v
            val revoked = (o["revoked"] as? JsonValue.Bool)?.v
            if (device == null || group == null || paired == null || revoked == null) throw bad("stored LAN peer is malformed")
            val name = when (val n = o["name"]) {
                is JsonValue.Str -> n.v
                null, JsonValue.Null -> null
                else -> throw bad("stored LAN peer name is malformed")
            }
            val endpoint = when (val e = o["endpoint"]) {
                is JsonValue.Obj -> try {
                    val f = Pairing.endpoint(e.fields["host"], e.fields["port"])
                    LanEndpoint(f.host, f.port)
                } catch (x: PairingException) {
                    throw bad("stored LAN peer endpoint is malformed")
                }
                null, JsonValue.Null -> null
                else -> throw bad("stored LAN peer endpoint is malformed")
            }
            val signing: ByteArray
            val exchange: ByteArray
            try {
                signing = LanTransport.b64(o["signing_public"], 32, "signing")
                exchange = LanTransport.b64(o["exchange_public"], 32, "exchange")
            } catch (x: Exception) {
                throw bad("stored LAN peer keys are malformed")
            }
            // `hello`: an integer is the pin; any other value is not one and is kept as it is (desktop `_entry_sealed`).
            val extras = LinkedHashMap(o.filterKeys { it !in KNOWN_FIELDS })
            var hello: Long? = null
            when (val h = o["hello"]) {
                is JsonValue.Int -> hello = h.v
                null -> {}
                else -> extras["hello"] = h
            }
            return LanPeer(device, group, name, endpoint, signing, exchange, paired, revoked, hello, extras)
        }
    }
}

/**
 * The LAN peer list of a group state and the host side of accepting an enrollment (desktop `lan_sync._with_peer`,
 * `LanResponder.enroll_verify` / `enroll_finish`, `MAX_LAN_PEERS`; Swift `LanPeers`).
 */
object LanPeers {
    /** Desktop `vault_bridge.MAX_LAN_PEERS`; revoked entries count. */
    const val MAX_PEERS = 16

    fun entry(state: SyncGroupState, deviceId: String): LanPeer? = state.lanPeers.firstOrNull { it.deviceId == deviceId }

    /**
     * A new Wi-Fi-only group with this device as its only member (desktop `lan_sync.create_lan_group`, Swift
     * `SyncGroup.createWiFi`): a fresh identity, a uuid4 group id, a random 32-byte key at epoch 1 and no cloud folder.
     * Randomness, in order: the identity ([DeviceIdentity.generate]), 16 bytes (group id), 32 (key). The caller stores
     * it (refusing when the vault is already in a group).
     */
    fun createWifiGroup(installId: String, random: RandomSource): SyncGroupState {
        if (installId.isEmpty() || app.localgatekeys.core.primitives.Scalars.count(installId) > app.localgatekeys.core.sync.FolderSync.MAX_INSTALL_ID ||
            installId.contains('\u0000')
        ) {
            throw app.localgatekeys.core.sync.FolderSyncException("bad-install-id", "install id must be a non-empty bounded string")
        }
        val identity = DeviceIdentity.generate(random = random)
        val u = random.bytes(16)
        if (u.size != 16) throw LanSyncException("bad-random")
        u[6] = ((u[6].toInt() and 0x0F) or 0x40).toByte()
        u[8] = ((u[8].toInt() and 0x3F) or 0x80).toByte()
        val h = Hex.lower(u)
        val groupId = h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20, 32)
        val gk = app.localgatekeys.core.group.GroupKey(groupId, 1, random.bytes(32))
        return SyncGroupState(gk.groupId, gk.epoch, gk.key, identity, installId, hasFolder = false)
    }

    /** [state] with [peer] listed (replacing an entry of the same id); `too-many-peers` past [MAX_PEERS]. */
    fun adding(peer: LanPeer, state: SyncGroupState): SyncGroupState {
        val others = state.lanPeers.filter { it.deviceId != peer.deviceId }
        if (others.size >= MAX_PEERS) throw LanSyncException("too-many-peers", "at most $MAX_PEERS LAN peers")
        return state.copy(lanPeers = others + peer)
    }

    /** [state] with [deviceId] marked revoked (kept listed); false when it was not listed. */
    fun revoking(deviceId: String, state: SyncGroupState): Pair<SyncGroupState, Boolean> {
        val i = state.lanPeers.indexOfFirst { it.deviceId == deviceId }
        if (i < 0) return state to false
        val list = state.lanPeers.toMutableList()
        list[i] = list[i].copy(revoked = true)
        return state.copy(lanPeers = list) to true
    }

    /** [state] with the listed peer [deviceId] pinned to the sealed hello; null when not listed or already pinned. */
    fun pinningSealed(deviceId: String, state: SyncGroupState): SyncGroupState? {
        val i = state.lanPeers.indexOfFirst { it.deviceId == deviceId }
        if (i < 0 || state.lanPeers[i].sealed) return null
        val list = state.lanPeers.toMutableList()
        list[i] = list[i].copy(hello = LanTransport.VERSION)
        return state.copy(lanPeers = list)
    }

    /** Saves the pin of [deviceId] in one commit; false when nothing was saved. */
    fun pinSealed(deviceId: String, store: ItemStore): Boolean = try {
        val snap = store.load()
        val next = snap.sync?.let { pinningSealed(deviceId, it) }
        if (next == null) {
            false
        } else {
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, next))
            true
        }
    } catch (e: Exception) {
        false
    }

    /** Device ids a new device may not take: listed peers (revoked ones too), keyring members and this device. */
    fun reservedIds(state: SyncGroupState): Set<String> =
        state.lanPeers.map { it.deviceId }.toSet() + state.members + state.deviceId

    /**
     * The listed entry a known device pairs again with (design 2026-11-17, rule 4): a paired Wi-Fi peer of [state]'s
     * group, not revoked, not this device, whose pinned signing and exchange keys both equal [request]'s (compared in
     * constant time). Null for everything else, which stays refused: this device's own id, a known id with other keys,
     * a revoked id, an id known only from the folder member list (no keys to compare here).
     */
    fun rejoining(state: SyncGroupState, request: Enrollment.Request): LanPeer? {
        if (request.deviceId == state.deviceId) return null
        val peer = entry(state, request.deviceId) ?: return null
        val signing = MessageDigest.isEqual(peer.signingPublic, request.signingPublic)
        val exchange = MessageDigest.isEqual(peer.exchangePublic, request.exchangePublic)
        return peer.takeIf { signing && exchange && !it.revoked && it.groupId == state.groupId }
    }

    /**
     * `enroll_verify`: one enrollment request for the armed [session]. An offer that is not of [state]'s group or not
     * made by this device stops the session and gets the generic refusal (no answer once it stopped listening); then
     * [OfferSession.handle] with the reserved ids, letting a known device with the same keys through ([rejoining]).
     */
    fun verifyEnrollment(raw: ByteArray, session: OfferSession, state: SyncGroupState?): OfferSession.Outcome {
        if (state == null || !matches(session.offer, state)) {
            val wasListening = session.isListening
            session.stop()
            return if (wasListening) OfferSession.refusal("refused") else OfferSession.Outcome.Close
        }
        return session.handle(raw, reservedIds(state), state.lanPeers.size, MAX_PEERS) { rejoining(state, it) != null }
    }

    internal fun matches(offer: PairingOffer, state: SyncGroupState): Boolean =
        offer.groupId == state.groupId && offer.inviterDeviceId == state.deviceId &&
            offer.inviterSigningPublic.contentEquals(state.identity.signingPublicKey) &&
            offer.inviterExchangePublic.contentEquals(state.identity.exchangePublicKey)

    /**
     * `enroll_finish` after Accept: re-checks the offer against the current [state] (group, inviter), the peer limit and
     * the reserved ids, then pins the new device and seals the group key to it. Returns the reply frame payload and the
     * state to commit; a refusal throws [PairingException.Kind.REFUSED] with the reason to answer (`refused` or `full`).
     * A device that paired through a version-2 offer is pinned to the sealed hello at once. [keepEndpoint] false stores
     * the peer without an endpoint (a phone host never dials its peers: they always initiate).
     *
     * A known device pairing again with the same keys ([rejoining], rule 4) replaces its entry in place (name, address,
     * pairing time, protocol pin) instead of adding one, and takes no new place under [MAX_PEERS]. What this device holds
     * for that id (its hello counter, its view counters and witnessed generation) stays, so an old session of it still
     * cannot be replayed.
     */
    fun acceptEnrollment(
        request: Enrollment.Request,
        offer: PairingOffer,
        state: SyncGroupState,
        now: Long,
        random: RandomSource,
        keepEndpoint: Boolean = true,
    ): Pair<ByteArray, SyncGroupState> {
        if (!matches(offer, state)) throw PairingException(PairingException.Kind.REFUSED, "refused")
        val known = rejoining(state, request)
        if (known == null && state.lanPeers.size >= MAX_PEERS) throw PairingException(PairingException.Kind.REFUSED, "full")
        if (known == null && request.deviceId in reservedIds(state)) throw PairingException(PairingException.Kind.REFUSED, "refused")
        val peer = LanPeer(
            request.deviceId, state.groupId, request.name, if (keepEndpoint) request.endpoint else null,
            request.signingPublic, request.exchangePublic, now,
            hello = if (request.hasReveal) LanTransport.VERSION else null,
        )
        val newState = if (known != null) {
            state.copy(lanPeers = state.lanPeers.map { if (it.deviceId == peer.deviceId) peer else it })
        } else {
            try {
                adding(peer, state)
            } catch (e: LanSyncException) {
                throw PairingException(PairingException.Kind.REFUSED, "full")
            }
        }
        val reply = Enrollment.sealReply(state.identity, offer, request, state.groupKey(), random)
        return reply to newState
    }
}
