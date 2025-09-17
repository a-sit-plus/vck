package at.asitplus.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

/**
 * Part of OpenID for Verifiable Presentations 1.0
 * [B.2.6.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.1)
 */
@Serializable
@CborArray
data class OpenId4VpHandover(
    /** Should be set to `OpenID4VPHandover`. */
    val type: String,
    /** The SHA-256 hash of [OpenId4VpHandoverInfo]. */
    @ByteString
    val hash: ByteArray,
) {
    init {
        require(type == TYPE_OPENID4VP)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OpenId4VpHandover

        if (type != other.type) return false
        if (!hash.contentEquals(other.hash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + hash.contentHashCode()
        return result
    }

    companion object {
        const val TYPE_OPENID4VP = "OpenID4VPHandover"
    }

}