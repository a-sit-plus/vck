package at.asitplus.dcapi

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

/**
 * Part of ISO 18013-7 Annex C and OpenID for Verifiable Presentations 1.0
 * [B.2.6.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.2)
 */
@Serializable
@CborArray
data class OpenID4VPDCAPIHandoverInfo(
    /** Origin of the request. It MUST NOT be prefixed with `origin:`. */
    val origin: String,
    /** The value of the `nonce` request parameter. */
    val nonce: String,
    /**
     * For the Response Mode `dc_api.jwt`, this element MUST be the JWK SHA-256 Thumbprint
     * as defined in [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638), encoded as a Byte String,
     * of the Verifier's public key used to encrypt the response.
     * If the Response Mode is `dc_api`, this element MUST be `null`. */
    @ByteString
    val jwkThumbprint: ByteArray?,
) : SessionTranscriptContentHashable {
    init {
        require(!origin.startsWith("origin:"))
    }

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

}