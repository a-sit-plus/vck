package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.third_party.kotlin.encodeBase64Url
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * 7.2.2.  Flattened JWS JSON Serialization Syntax
 *
 *    The flattened JWS JSON Serialization syntax is based upon the general
 *    syntax but flattens it, optimizing it for the single digital
 *    signature/MAC case.  It flattens it by removing the "signatures"
 *    member and instead placing those members defined for use in the
 *    "signatures" array (the "protected", "header", and "signature"
 *    members) in the top-level JSON object (at the same level as the
 *    "payload" member).
 *
 *    The "signatures" member MUST NOT be present when using this syntax.
 *    Other than this syntax difference, JWS JSON Serialization objects
 *    using the flattened syntax are processed identically to those using
 *    the general syntax.
 *
 *    In summary, the syntax of a JWS using the flattened JWS JSON
 *    Serialization is as follows:
 *
 *      {
 *       "payload":"<payload contents>",
 *       "protected":"<integrity-protected header contents>",
 *       "header":<non-integrity-protected header contents>,
 *       "signature":"<signature contents>"
 *      }
 *
 *    See Appendix A.7 for an example JWS using the flattened JWS JSON
 *    Serialization syntax.
 *
 *      At least one of the "protected" and "header" members MUST be present
 *    for each signature/MAC computation so that an "alg" Header Parameter
 *    value is conveyed.
 *
 *    Additional members can be present in both the JSON objects defined
 *    above; if not understood by implementations encountering them, they
 *    MUST be ignored.
 */
@Serializable
data class FlattenedJsonJws(
    /**
     *       The "protected" member MUST be present and contain the value
     *       BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected
     *       Header value is non-empty; otherwise, it MUST be absent.  These
     *       Header Parameter values are integrity protected.
     */
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    @SerialName("protected")
    val protected: ByteArray? = null,
    /**
     *       The "header" member MUST be present and contain the value JWS
     *       Unprotected Header when the JWS Unprotected Header value is non-
     *       empty; otherwise, it MUST be absent.  This value is represented as
     *       an unencoded JSON object, rather than as a string.  These Header
     *       Parameter values are not integrity protected.
     */
    @SerialName("header")
    val header: JsonObject? = null,
    /**
     *       The "payload" member MUST be present and contain the value
     *       BASE64URL(JWS Payload).
     */
    @SerialName("payload")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val payload: ByteArray,
    /**
     *       The "signature" member MUST be present and contain the value
     *       BASE64URL(JWS Signature).
     */
    @SerialName("signature")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val signature: ByteArray,
) {
    init {
        if (header == null && protected == null) {
            throw IllegalArgumentException("At least one of the \"protected\" and \"header\" members MUST be present for each signature/MAC computation so that an \"alg\" Header Parameter value is conveyed.")
        }
        if (header != null) {
            protectedDecoded?.keys?.forEach {
                if (header.keys.contains(it)) {
                    throw IllegalArgumentException("The Header Parameter names provided as keys in the arguments `protected` and `header` MUST be disjoint.")
                }
            }
        }
    }

    private val protectedDecoded: JsonObject?
        get() = protected?.let {
            vckJsonSerializer.decodeFromString<JsonObject>(it.decodeToString())
        }

    val joseHeader: JsonObject
        get() = buildJsonObject {
            header?.forEach {
                put(it.key, it.value)
            }
            protectedDecoded?.forEach {
                put(it.key, it.value)
            }
        }

    val signatureInput: ByteArray
        get() {
            val protectedHeaderString = (protected?.encodeBase64Url() ?: "")
            return "$protectedHeaderString.${payload.encodeBase64Url()}".encodeToByteArray()
        }

    fun toJwsSigned(): JwsSigned<ByteArray> {
        val header = Json.decodeFromJsonElement<JwsHeader>(joseHeader)
        return JwsSigned(
            header = header,
            payload = payload,
            signature = with(signature) {
                // taken from [JwsSigned.deserialize]
                when (val curve = header.algorithm.ecCurve) {
                    null -> at.asitplus.signum.indispensable.CryptoSignature.RSAorHMAC(this)
                    else -> at.asitplus.signum.indispensable.CryptoSignature.EC.fromRawBytes(curve, this)
                }
            },
            plainSignatureInput = signatureInput,
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as FlattenedJsonJws

        if (protectedDecoded != other.protectedDecoded) return false
        if (header != other.header) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedDecoded?.hashCode() ?: 0
        result = 31 * result + (header?.hashCode() ?: 0)
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}