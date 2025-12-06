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
data class OpenId4VpHandoverInfo(
    /** MUST be the `client_id` request parameter. If applicable, this includes the Client Identifier Prefix.
     * Must be null if DC API unsigned requests are used. */
    val clientId: String?,
    /** MUST be the value of the `nonce` request parameter. */
    val nonce: String,
    /**
     * If the response is encrypted, e.g., using `direct_post.jwt`, this MUST be the JWK SHA-256 Thumbprint as defined
     * in [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638), encoded as a Byte String, of the Verifier's public
     * key used to encrypt the response. Otherwise, this MUST be `null`.
     */
    @ByteString
    val jwkThumbprint: ByteArray?,
    /**
     * MUST be either the `redirect_uri` or `response_uri` request parameter, depending on which is present,
     * as determined by the Response Mode.
     */
    val responseUrl: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OpenId4VpHandoverInfo

        if (clientId != other.clientId) return false
        if (nonce != other.nonce) return false
        if (!jwkThumbprint.contentEquals(other.jwkThumbprint)) return false
        if (responseUrl != other.responseUrl) return false

        return true
    }

    override fun hashCode(): Int {
        var result = clientId.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + jwkThumbprint.contentHashCode()
        result = 31 * result + responseUrl.hashCode()
        return result
    }

}