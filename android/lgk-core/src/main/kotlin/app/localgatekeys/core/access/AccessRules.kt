package app.localgatekeys.core.access

import app.localgatekeys.core.json.JsonValue
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Locale

/**
 * Per-login access rules (feature pack contract 2026-11-15 §4): the synced `scope.access` object plus the existing
 * `policy.require_master_password` / `policy.fill`. Reading follows "unknown = strictest": an `access` that is not an
 * object, or holds a key other than [KEYS], turns every rule on. Enforcement never depends on the plan.
 */
object AccessRules {
    enum class DeviceClass(val wire: String) {
        PHONE("phone"), COMPUTER("computer");

        companion object {
            fun of(wire: String): DeviceClass = entries.firstOrNull { it.wire == wire } ?: PHONE
        }
    }

    /**
     * What a device applies to one login. [unknownRule]: `scope.access` came from a newer version (or is damaged), so
     * every rule is on. [expiresOn]: the valid `expires` date (for the banner), "" otherwise.
     */
    data class Effective(
        val reauth: Boolean,
        val autofill: Boolean,
        val copyOnce: Boolean,
        val phoneView: Boolean,
        val expired: Boolean,
        val unknownRule: Boolean = false,
        val expiresOn: String = "",
    ) {
        /** Whether a phone refuses copy, autofill, share and export ([phoneView]). */
        fun phoneRefuses(device: DeviceClass): Boolean = phoneView && device == DeviceClass.PHONE

        /** Any rule at all is on (export asks once; the agent gates leave the login out). */
        val anyRule: Boolean get() = reauth || !autofill || copyOnce || phoneView || expired || unknownRule
    }

    val KEYS: Set<String> = setOf("copy", "phones", "expires")
    val NONE = Effective(reauth = false, autofill = true, copyOnce = false, phoneView = false, expired = false)

    private val isoDay: DateTimeFormatter = DateTimeFormatter.ofPattern("uuuu-MM-dd", Locale.ROOT).withResolverStyle(ResolverStyle.STRICT)

    /** A valid `YYYY-MM-DD` (dash form only, a real calendar day, year ≥ 1), or null. */
    fun isoDate(s: String): LocalDate? {
        if (s.length != 10 || s[4] != '-' || s[7] != '-') return null
        if (!s.withIndex().all { (i, c) -> i == 4 || i == 7 || c in '0'..'9' }) return null
        return try {
            LocalDate.parse(s, isoDay).takeIf { it.year >= 1 }
        } catch (e: Exception) {
            null
        }
    }

    private fun obj(v: JsonValue?): Map<String, JsonValue>? = (v as? JsonValue.Obj)?.fields

    /** The login's raw `scope.access` value, or null when it has none. */
    fun accessOf(record: Map<String, JsonValue>): JsonValue? = obj(record["scope"])?.get("access")

    /**
     * Whether a `policy` asks to re-authenticate: any `require_master_password` other than `false` (unknown =
     * strictest, so a malformed value is never read as off; scan A-L1).
     */
    fun strictPolicy(policy: Map<String, JsonValue>): Boolean = policy["require_master_password"].let { it != null && it != JsonValue.Bool(false) }

    /** `effective(record, device_class, today)` (§4.2); [today] is the device's local `YYYY-MM-DD`. */
    fun effective(record: Map<String, JsonValue>, device: DeviceClass, today: String): Effective {
        val policy = obj(record["policy"]) ?: emptyMap()
        val fillClick = (policy["fill"] ?: JsonValue.Str("click")) == JsonValue.Str("click")
        val strict = strictPolicy(policy)
        val raw = accessOf(record)
        if (raw != null) {
            val a = obj(raw)
            if (a == null || !KEYS.containsAll(a.keys)) {
                return Effective(reauth = true, autofill = false, copyOnce = true, phoneView = true, expired = false, unknownRule = true)
            }
        }
        val a = obj(raw) ?: emptyMap()
        val copyOnce = a["copy"]?.let { it != JsonValue.Str("normal") } ?: false
        val phoneView = a["phones"]?.let { it != JsonValue.Str("full") } ?: false
        var expired = false
        var expiresOn = ""
        val e = a["expires"]
        if (e != null && e != JsonValue.Str("")) {
            val date = (e as? JsonValue.Str)?.v?.let(::isoDate)
            val now = isoDate(today)
            if (date == null) {
                expired = true
            } else {
                expiresOn = (e as JsonValue.Str).v
                expired = now == null || !now.isBefore(date)
            }
        }
        val reauth = strict || expired
        val autofill = fillClick && !expired && !(phoneView && device == DeviceClass.PHONE)
        return Effective(reauth, autofill, copyOnce, phoneView, expired, false, expiresOn)
    }

    /** The access rules a person sets on a login (the write form drops defaults). */
    data class Settings(val copyOnce: Boolean = false, val phonesView: Boolean = false, val expires: String = "") {
        /** Only non-default keys; null when nothing is set (the key is then removed). */
        fun write(): JsonValue? {
            val m = LinkedHashMap<String, JsonValue>()
            if (copyOnce) m["copy"] = JsonValue.Str("once")
            if (phonesView) m["phones"] = JsonValue.Str("view")
            if (expires.isNotEmpty()) m["expires"] = JsonValue.Str(expires)
            return if (m.isEmpty()) null else JsonValue.Obj(m)
        }

        companion object {
            /** What the settings screen starts from; an unknown or damaged value reads as everything on. */
            fun of(raw: JsonValue?): Settings {
                if (raw == null) return Settings()
                val a = obj(raw)
                if (a == null || !KEYS.containsAll(a.keys)) return Settings(copyOnce = true, phonesView = true)
                val exp = (a["expires"] as? JsonValue.Str)?.v ?: ""
                return Settings(
                    copyOnce = a["copy"]?.let { it != JsonValue.Str("normal") } ?: false,
                    phonesView = a["phones"]?.let { it != JsonValue.Str("full") } ?: false,
                    expires = exp,
                )
            }
        }
    }

    /**
     * [record] with its `scope.access` set to [access] (null removes it). Every other scope key stays as it is. The
     * caller sets `updated_at`.
     */
    fun withAccess(record: Map<String, JsonValue>, access: JsonValue?): Map<String, JsonValue> {
        val scope = LinkedHashMap(obj(record["scope"]) ?: emptyMap())
        if (access == null) scope.remove("access") else scope["access"] = access
        val out = LinkedHashMap(record)
        out["scope"] = JsonValue.Obj(scope)
        return out
    }

    /** [record] with `policy.require_master_password` and `policy.fill` set; other policy keys kept. */
    fun withPolicy(record: Map<String, JsonValue>, reauth: Boolean, neverFill: Boolean): Map<String, JsonValue> {
        val p = LinkedHashMap(obj(record["policy"]) ?: emptyMap())
        p["require_master_password"] = JsonValue.Bool(reauth)
        p["fill"] = JsonValue.Str(if (neverFill) "never" else "click")
        val out = LinkedHashMap(record)
        out["policy"] = JsonValue.Obj(p)
        return out
    }

    /**
     * Whether going from [old] to [new] (both full login records) sets or tightens a rule: that needs Pro
     * (`access_policies`). Loosening or removing never does.
     */
    fun tightens(old: Map<String, JsonValue>, new: Map<String, JsonValue>): Boolean {
        val today = "0001-01-01" // date-independent: compare the stored values
        val o = effective(old, DeviceClass.COMPUTER, today)
        val n = effective(new, DeviceClass.COMPUTER, today)
        val op = obj(old["policy"]) ?: emptyMap()
        val np = obj(new["policy"]) ?: emptyMap()
        if (strictPolicy(np) && !strictPolicy(op)) return true
        if ((np["fill"] ?: JsonValue.Str("click")) != JsonValue.Str("click") && (op["fill"] ?: JsonValue.Str("click")) == JsonValue.Str("click")) return true
        if (n.unknownRule && !o.unknownRule) return true
        if (n.copyOnce && !o.copyOnce) return true
        if (n.phoneView && !o.phoneView) return true
        val oe = (obj(accessOf(old))?.get("expires") as? JsonValue.Str)?.v ?: ""
        val ne = (obj(accessOf(new))?.get("expires") as? JsonValue.Str)?.v ?: ""
        if (ne.isNotEmpty() && (oe.isEmpty() || ne < oe)) return true
        return false
    }

    /**
     * The stricter of two `scope.access` values (the merge, §3.2 / §4.2): per key the stricter value, `expires` the
     * earlier date (a malformed date counts as already expired, so it wins). Keys this version does not know are kept
     * (first [a]'s, then [b]'s), since they mean "strictest" to every reader. A value that is not an object is the
     * strictest of all and is kept as it is. Null = no access rules (absent or JSON null; Python `stricter_access`, so
     * rules left only at their defaults come out as null).
     */
    fun stricter(a: JsonValue?, b: JsonValue?): JsonValue? {
        val a0 = a?.takeUnless { it == JsonValue.Null }
        val b0 = b?.takeUnless { it == JsonValue.Null }
        if (a0 != null && obj(a0) == null) return a0
        if (b0 != null && obj(b0) == null) return b0
        val ao = obj(a0) ?: emptyMap()
        val bo = obj(b0) ?: emptyMap()
        val out = LinkedHashMap<String, JsonValue>()
        fun nonDefault(v: JsonValue?, default: String): Boolean = v != null && v != JsonValue.Str(default)
        val copy = when {
            nonDefault(ao["copy"], "normal") -> ao["copy"]
            nonDefault(bo["copy"], "normal") -> bo["copy"]
            else -> null
        }
        if (copy != null) out["copy"] = copy
        val phones = when {
            nonDefault(ao["phones"], "full") -> ao["phones"]
            nonDefault(bo["phones"], "full") -> bo["phones"]
            else -> null
        }
        if (phones != null) out["phones"] = phones
        val expires = earlier(ao["expires"], bo["expires"])
        if (expires != null) out["expires"] = expires
        for ((k, v) in ao) if (k !in KEYS) out[k] = v
        for ((k, v) in bo) if (k !in KEYS && k !in out) out[k] = v
        return if (out.isEmpty()) null else JsonValue.Obj(out)
    }

    private fun earlier(a: JsonValue?, b: JsonValue?): JsonValue? {
        fun set(v: JsonValue?): Boolean = v != null && v != JsonValue.Str("")
        if (!set(a)) return if (set(b)) b else null
        if (!set(b)) return a
        val ad = (a as? JsonValue.Str)?.v?.let(::isoDate) ?: return a
        val bd = (b as? JsonValue.Str)?.v?.let(::isoDate) ?: return b
        return if (bd.isBefore(ad)) b else a
    }

    /**
     * The merge rule for `policy` (Python `access_policy.stricter_policy`): the keeper's policy ([a]) tightened by [b]:
     * never fill and re-authenticate win; every other key is the keeper's, and nothing of [b] is copied over otherwise
     * (scan A-L13). A keeper's non-boolean `require_master_password` is strict and written back as `true`. Null when
     * neither side is an object (the keeper's value then stays as it is) or when only [b] is one and adds nothing.
     */
    fun stricterPolicy(a: JsonValue?, b: JsonValue?): JsonValue? {
        val ao = obj(a)
        val bo = obj(b)
        if (ao == null && bo == null) return null
        val out = LinkedHashMap(ao ?: emptyMap())
        if (out.containsKey("require_master_password") && out["require_master_password"] != JsonValue.Bool(false)) {
            out["require_master_password"] = JsonValue.Bool(true)
        }
        if (bo != null) {
            val bFill = bo["fill"]
            if (bFill != null && bFill != JsonValue.Str("click")) out["fill"] = JsonValue.Str("never")
            if (strictPolicy(bo)) out["require_master_password"] = JsonValue.Bool(true)
        }
        return if (ao != null || out.isNotEmpty()) JsonValue.Obj(out) else null
    }
}
