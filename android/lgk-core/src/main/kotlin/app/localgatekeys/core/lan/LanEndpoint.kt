package app.localgatekeys.core.lan

import app.localgatekeys.core.json.JsonValue

/**
 * A literal LAN endpoint with a normalised host. The constructor validates like the desktop
 * `LANEndpoint` / `_private_lan_endpoint` and throws [PairingException] (MALFORMED); validating an
 * already-normalised host is idempotent.
 */
class LanEndpoint(host: String, port: Int) {
    val host: String
    val port: Int

    init {
        val e = Pairing.endpoint(JsonValue.Str(host), JsonValue.Int(port.toLong()))
        this.host = e.host
        this.port = e.port
    }

    internal val json: JsonValue
        get() = JsonValue.Obj(mapOf("host" to JsonValue.Str(host), "port" to JsonValue.Int(port.toLong())))

    override fun equals(other: Any?): Boolean = other is LanEndpoint && host == other.host && port == other.port

    override fun hashCode(): Int = host.hashCode() * 31 + port

    override fun toString(): String = "LanEndpoint(host=$host, port=$port)"
}
