package app.localgatekeys.android.pro

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.License
import app.localgatekeys.core.records.LicenseException
import app.localgatekeys.core.records.LicenseInfo
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.sync.StoreSnapshot

/** The free plan's item limit. */
object ItemLimit {
    const val FREE_ITEMS = 4

    enum class Action { CREATE, RESTORE, EDIT, DELETE, AUTOFILL }

    /** Live synced items: logins and typed items; tombstones, licence states and kinds that never sync excluded. */
    fun liveCount(s: StoreSnapshot): Int = s.records.entries.count { (id, wrapper) ->
        if (s.meta[id]?.deleted == true) return@count false
        val w = (wrapper as? JsonValue.Obj)?.fields ?: return@count false
        val ns = (w["ns"] as? JsonValue.Str)?.v ?: return@count false
        val r = (w["record"] as? JsonValue.Obj)?.fields ?: return@count false
        ns != Namespace.LICENSE.wire && r["kind"] != JsonValue.Str("document")
    }

    /** Only creating or restoring needs a free slot or Pro; nothing that exists is ever blocked. */
    fun allows(a: Action, s: StoreSnapshot, isPro: Boolean): Boolean = when (a) {
        Action.CREATE, Action.RESTORE -> isPro || liveCount(s) < FREE_ITEMS
        Action.EDIT, Action.DELETE, Action.AUTOFILL -> true
    }

    /** The first stored licence state (in code point order of its id) that verifies under [keys]. */
    fun validLicense(s: StoreSnapshot, keys: Map<String, ByteArray>): LicenseInfo? {
        if (keys.isEmpty()) return null
        for ((id, wrapper) in s.records.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            if (!Scalars.hasPrefix(id, License.ID_PREFIX)) continue
            val w = (wrapper as? JsonValue.Obj)?.fields ?: continue
            if (w["ns"] != JsonValue.Str(Namespace.LICENSE.wire)) continue
            val bundle = w["record"] ?: continue
            val info = try {
                License.verify(bundle, keys)
            } catch (e: LicenseException) {
                continue
            }
            if (License.stateId(info.licenseId) != id) continue
            return info
        }
        return null
    }
}
