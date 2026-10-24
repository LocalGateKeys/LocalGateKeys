package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.Hex
import java.security.MessageDigest

/** A peer device pinned by the group: its keys and, when known, its LAN endpoint. */
data class PinnedPeer(
    val deviceId: String,
    val groupId: String,
    val signingPublic: ByteArray,
    val exchangePublic: ByteArray,
    val endpoint: LanEndpoint?,
) {
    /** Lowercase hex SHA-256 of the signing key. */
    val fingerprint: String get() = Hex.lower(MessageDigest.getInstance("SHA-256").digest(signingPublic))

    override fun equals(other: Any?): Boolean =
        other is PinnedPeer && deviceId == other.deviceId && groupId == other.groupId &&
            signingPublic.contentEquals(other.signingPublic) && exchangePublic.contentEquals(other.exchangePublic) &&
            endpoint == other.endpoint

    override fun hashCode(): Int =
        (((deviceId.hashCode() * 31 + groupId.hashCode()) * 31 + signingPublic.contentHashCode()) * 31 +
            exchangePublic.contentHashCode()) * 31 + (endpoint?.hashCode() ?: 0)
}
