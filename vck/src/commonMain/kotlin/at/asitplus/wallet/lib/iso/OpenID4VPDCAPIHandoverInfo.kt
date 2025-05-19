package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of OpenID for Verifiable Presentations - draft 26 (B.3.5.1)
 */
@Serializable
@CborArray
data class OpenID4VPDCAPIHandoverInfo(
    /** Origin of the request. It MUST NOT be prefixed with `origin:` */
    val origin: String,
    /** the value of the nonce request parameter */
    val nonce: String,
    /** For the Response Mode dc_api.jwt, the third element MUST be the JWK SHA-256 Thumbprint
     * of the Verifier's public key used to encrypt the response.
     * If the Response Mode is dc_api, the third element MUST be null */
    @ByteString
    val jwkThumbprint: ByteArray?
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OpenID4VPDCAPIHandoverInfo

        if (origin != other.origin) return false
        if (nonce != other.nonce) return false
        if (!jwkThumbprint.contentEquals(other.jwkThumbprint)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = origin.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + jwkThumbprint.contentHashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<OpenID4VPDCAPIHandoverInfo>(it)
        }.wrap()
    }

}