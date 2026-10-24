package app.localgatekeys.android.pro

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import java.io.File

/** The desktop's TEST-ONLY licence vector (never verifies with the production key). */
object LicenseVector {
    data class Vector(val keys: Map<String, ByteArray>, val id: String, val wrapper: JsonValue)

    fun load(): Vector {
        val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
        val o = CanonicalJson.parse(File(repo, "tests/vectors/sync/license_state.json").readBytes()).obj().fields
        val keys = mapOf(o.getValue("key_id").str() to Base64Std.decodeStrict(o.getValue("public_key_b64").str()))
        return Vector(keys, o.getValue("state_id").str(), o.getValue("wrapper"))
    }
}
