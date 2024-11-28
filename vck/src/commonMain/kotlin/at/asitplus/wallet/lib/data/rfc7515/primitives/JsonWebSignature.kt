package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * 7.2.1.  General JWS JSON Serialization Syntax
 */
@Serializable
data class JsonWebSignature(
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
    val signatures: List<JwsSignatureEntry>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebSignature

        if (!payload.contentEquals(other.payload)) return false
        if (signatures != other.signatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.contentHashCode()
        result = 31 * result + signatures.hashCode()
        return result
    }

    companion object {
        /**
         *    1.  Parse the JWS representation to extract the serialized values for
         *        the components of the JWS.  When using the JWS Compact
         *        Serialization, these components are the base64url-encoded
         *        representations of the JWS Protected Header, the JWS Payload, and
         *        the JWS Signature, and when using the JWS JSON Serialization,
         *        these components also include the unencoded JWS Unprotected
         *        Header value.  When using the JWS Compact Serialization, the JWS
         *        Protected Header, the JWS Payload, and the JWS Signature are
         *        represented as base64url-encoded values in that order, with each
         *        value being separated from the next by a single period ('.')
         *        character, resulting in exactly two delimiting period characters
         *        being used. The JWS JSON Serialization is described in
         *        Section 7.2.
         *
         *    2.  Base64url-decode the encoded representation of the JWS Protected
         *        Header, following the restriction that no line breaks,
         *        whitespace, or other additional characters have been used.
         *
         *    3.  Verify that the resulting octet sequence is a UTF-8-encoded
         *        representation of a completely valid JSON object conforming to
         *        RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON
         *        object.
         */
        fun deserialize(input: String, json: Json = Json): JsonWebSignature =
            if (input.startsWith("{")) {
                val jsonJwsSigned = json.decodeFromString<JsonObject>(input)
                if (jsonJwsSigned.containsKey("signatures")) {
                    json.decodeFromJsonElement<JsonWebSignature>(jsonJwsSigned)
                } else {
                    json.decodeFromJsonElement<FlattenedJsonWebSignature>(jsonJwsSigned).toJsonWebSignature()
                }
            } else {
                CompactJsonWebSignature.deserialize(input).toFlattenedJsonWebSignature().toJsonWebSignature()
            }
    }
}

