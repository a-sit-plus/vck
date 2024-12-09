package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 7.2.1.  General JWS JSON Serialization Syntax
 */
@Serializable
data class GeneralJsonJws(
    /**
     *       The "payload" member MUST be present and contain the value
     *       BASE64URL(JWS Payload).
     */
    @SerialName("payload")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val payload: ByteArray,
    /**
     *       The "signatures" member value MUST be an array of JSON objects.
     *       Each object represents a signature or MAC over the JWS Payload and
     *       the JWS Protected Header.
     */
    val signatures: List<GeneralJsonJwsSignature>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as GeneralJsonJws

        if (!payload.contentEquals(other.payload)) return false
        if (signatures != other.signatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.contentHashCode()
        result = 31 * result + signatures.hashCode()
        return result
    }
}