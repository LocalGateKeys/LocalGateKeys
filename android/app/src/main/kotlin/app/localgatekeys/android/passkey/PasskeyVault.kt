package app.localgatekeys.android.passkey

import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.Passkey
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/** A passkey the person can choose; no key material. */
data class PasskeyCandidate(val itemId: String, val title: String, val rpId: String, val userName: String, val credentialId: ByteArray) {
    override fun equals(other: Any?): Boolean = other is PasskeyCandidate && itemId == other.itemId && credentialId.contentEquals(other.credentialId)
    override fun hashCode(): Int = itemId.hashCode()
    override fun toString(): String = "PasskeyCandidate(itemId=$itemId, rpId=$rpId)"
}

class PasskeyAssertion(val credentialId: ByteArray, val authenticatorData: ByteArray, val signature: ByteArray, val userHandle: ByteArray) {
    override fun toString(): String = "PasskeyAssertion"
}

class PasskeyRegistration(
    val itemId: String,
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val attestationObject: ByteArray,
    val spki: ByteArray,
) {
    override fun toString(): String = "PasskeyRegistration(itemId=$itemId)"
}

/** Port of iOS `PasskeyVault` (ios/AutoFill/PasskeyFlow.swift): the work on an unlocked store, no UI. */
object PasskeyVault {
    /** The stored rp id is casefolded; the system may pass any case. Exact host only, never parent or child. */
    fun matches(r: PasskeyRecord, rpId: String): Boolean = r.rpId.isNotEmpty() && r.rpId == PasskeyRecord.normaliseRpId(rpId)

    fun live(s: StoreSnapshot, id: String): PasskeyRecord? {
        if (s.meta[id]?.deleted == true) return null
        return PasskeyRecord.from(s.records[id] ?: return null, id)
    }

    /** Usable passkeys for [rpId] ordered by item id; a non-empty [allowed] keeps only those credential ids. */
    fun candidates(s: StoreSnapshot, rpId: String, allowed: List<ByteArray>): List<PasskeyCandidate> =
        s.records.keys.sortedWith { a, b -> Scalars.compare(a, b) }.mapNotNull { id ->
            val r = live(s, id) ?: return@mapNotNull null
            if (r.key == null || !matches(r, rpId)) return@mapNotNull null
            if (allowed.isNotEmpty() && allowed.none { it.contentEquals(r.credentialId) }) return@mapNotNull null
            PasskeyCandidate(r.itemId, r.title, r.rpId, r.userName, r.credentialId)
        }

    /** Signs `authenticatorData || clientDataHash`. Never writes the item (counter stays 0). */
    fun assert(s: StoreSnapshot, itemId: String, rpId: String, clientDataHash: ByteArray, userVerified: Boolean): PasskeyAssertion {
        val r = live(s, itemId)?.takeIf { matches(it, rpId) } ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val key = r.key ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val ad = Passkey.authenticatorData(r.rpId, userVerified, null)
        return PasskeyAssertion(r.credentialId, ad, key.sign(ad, clientDataHash), r.userHandle)
    }

    /** True when a passkey with one of [exclude]'s credential ids is already stored for [rpId]. */
    fun excluded(s: StoreSnapshot, rpId: String, exclude: List<ByteArray>): Boolean =
        exclude.isNotEmpty() && candidates(s, rpId, exclude).isNotEmpty()

    /**
     * A new ES256 passkey item shaped as desktop `create_credential` writes it. Refused before any key is made when
     * the free plan is full and [isPro] says no; re-checked on the commit base; one retry on a stale base.
     */
    fun register(
        store: ItemStore,
        rpId: String,
        rpName: String,
        userName: String,
        userDisplayName: String,
        userHandle: ByteArray,
        exclude: List<ByteArray>,
        now: Long,
        today: String,
        random: RandomSource,
        isPro: (StoreSnapshot) -> Boolean,
        newKey: () -> PasskeyKey = { PasskeyKey.generate() },
    ): PasskeyRegistration {
        val first = store.load()
        if (excluded(first, rpId, exclude)) throw WebAuthnException(WebAuthnException.Reason.EXCLUDED)
        if (!ItemLimit.allows(ItemLimit.Action.CREATE, first, false) && !isPro(first)) throw WebAuthnException(WebAuthnException.Reason.NEEDS_PRO)
        val key = newKey()
        val credentialId = random.bytes(Passkey.CREDENTIAL_ID_LENGTH)
        val made = PasskeyRecord.newPayload(rpId, rpName, userName, userDisplayName, userHandle, credentialId, key, today)
        val stamp = JsonValue.Int(now)
        val id = EditorModel.uuid4(random)
        val record = Normalise.normalForm(
            Namespace.ITEM,
            JsonValue.Obj(
                linkedMapOf(
                    "id" to JsonValue.Str(id), "kind" to JsonValue.Str("passkey"), "title" to JsonValue.Str(made.title),
                    "payload" to made.fields, "created_at" to stamp, "updated_at" to stamp,
                    "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
                ),
            ),
        )
        val wrapper = Wrapper.make(Namespace.ITEM, record)
        var base: StoreSnapshot? = first
        for (attempt in 0 until 2) {
            val snap = base ?: store.load()
            base = null
            if (!ItemLimit.allows(ItemLimit.Action.CREATE, snap, false) && !isPro(snap)) throw WebAuthnException(WebAuthnException.Reason.NEEDS_PRO)
            if (snap.records[id] != null) throw WebAuthnException(WebAuthnException.Reason.STORE_BUSY)
            val records = LinkedHashMap(snap.records)
            records[id] = wrapper
            try {
                store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            } catch (e: Exception) {
                if (attempt == 0 && isStale(e)) continue
                throw WebAuthnException(WebAuthnException.Reason.STORE_BUSY)
            }
            val pub = key.publicKey
            val ad = Passkey.authenticatorData(PasskeyRecord.normaliseRpId(rpId), true, credentialId to Passkey.coseEs256Key(pub))
            return PasskeyRegistration(id, credentialId, ad, Passkey.noneAttestationObject(ad), pub.encoded)
        }
        throw WebAuthnException(WebAuthnException.Reason.STORE_BUSY)
    }

    /** `LocalStore`'s stale-base refusal (and the test store's `check`). */
    private fun isStale(e: Exception): Boolean =
        (e is app.localgatekeys.android.vault.LocalStoreException && e.kind == app.localgatekeys.android.vault.LocalStoreException.Kind.STALE) ||
            (e is IllegalStateException && e.message == "stale")
}
