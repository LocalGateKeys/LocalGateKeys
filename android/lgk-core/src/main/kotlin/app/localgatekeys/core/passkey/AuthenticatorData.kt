package app.localgatekeys.core.passkey

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

/** Port of Swift `Passkey/AuthenticatorData.swift`. */
object Passkey {
    /** b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41 */
    private val AAGUID_BYTES = byteArrayOf(
        0xb7.toByte(), 0xd2.toByte(), 0xa6.toByte(), 0xf0.toByte(), 0x1c, 0x4e, 0x4a, 0x5b,
        0x9e.toByte(), 0x3d, 0x5a, 0x1f, 0x7c, 0x2e, 0x8d.toByte(), 0x41,
    )

    /** A copy of the 16-byte AAGUID. */
    val AAGUID: ByteArray get() = AAGUID_BYTES.copyOf()
    const val CREDENTIAL_ID_LENGTH = 16

    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_BE = 0x08
    private const val FLAG_BS = 0x10
    private const val FLAG_AT = 0x40

    /**
     * SHA-256(rpId) || flags || 00000000 [|| AAGUID || len(credId) u16 BE || credId || COSE key].
     * Flags UP|BE|BS, +UV when [userVerified], +AT when [attested] (credential id, COSE key) is given.
     */
    fun authenticatorData(rpId: String, userVerified: Boolean, attested: Pair<ByteArray, ByteArray>?): ByteArray {
        var flags = FLAG_UP or FLAG_BE or FLAG_BS
        if (userVerified) flags = flags or FLAG_UV
        if (attested != null) flags = flags or FLAG_AT
        val out = ByteArrayOutputStream()
        out.write(MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8)))
        out.write(flags)
        out.write(ByteArray(4))
        if (attested != null) {
            val (credId, cose) = attested
            require(credId.size <= 0xFFFF) { "credential id length must fit in u16" }
            out.write(AAGUID_BYTES)
            out.write((credId.size shr 8) and 0xFF)
            out.write(credId.size and 0xFF)
            out.write(credId)
            out.write(cose)
        }
        return out.toByteArray()
    }

    /** x or y as exactly 32 big-endian bytes (left-padded, no sign byte). */
    internal fun coordinate(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray()
        val trimmed = if (raw.size > 1 && raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
        require(trimmed.size <= 32) { "coordinate longer than 32 bytes" }
        return ByteArray(32 - trimmed.size) + trimmed
    }

    /** COSE_Key `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in that order. */
    fun coseEs256Key(pub: ECPublicKey): ByteArray = Cbor.Mapping(
        listOf(
            Cbor.Integer(1) to Cbor.Integer(2),
            Cbor.Integer(3) to Cbor.Integer(-7),
            Cbor.Integer(-1) to Cbor.Integer(1),
            Cbor.Integer(-2) to Cbor.Bytes(coordinate(pub.w.affineX)),
            Cbor.Integer(-3) to Cbor.Bytes(coordinate(pub.w.affineY)),
        ),
    ).encoded()

    /** `{"fmt": "none", "attStmt": {}, "authData": ...}` in desktop key order. */
    fun noneAttestationObject(authData: ByteArray): ByteArray = Cbor.Mapping(
        listOf(
            Cbor.Text("fmt") to Cbor.Text("none"),
            Cbor.Text("attStmt") to Cbor.Mapping(emptyList()),
            Cbor.Text("authData") to Cbor.Bytes(authData),
        ),
    ).encoded()
}
