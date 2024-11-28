package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.rfc7515.headers.JwsCriticalHeaderParameterSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

/**
 *    At least one of the "protected" and "header" members MUST be present
 *    for each signature/MAC computation so that an "alg" Header Parameter
 *    value is conveyed.
 *
 *    Additional members can be present in both the JSON objects defined
 *    above; if not understood by implementations encountering them, they
 *    MUST be ignored.
 */
@Serializable
data class JwsSignatureEntry(
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
     *       The "signature" member MUST be present and contain the value
     *       BASE64URL(JWS Signature).
     */
    @SerialName("signature")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val signature: ByteArray,
) {
    init {
        if (header == null && protected == null) {
            throw IllegalArgumentException("At least one of the members `protected` and `header` MUST be present for each signature/MAC computation so that an `alg` Header Parameter value is conveyed.")
        }
        if (header != null) {
            val protectedHeader = protectedHeaderDecoded
            protectedHeader?.keys?.forEach {
                if (header.keys.contains(it)) {
                    throw IllegalArgumentException("The Header Parameter names provided as keys in the arguments `protected` and `header` MUST be disjoint.")
                }
            }

            /**
             * When used, this Header Parameter MUST be integrity protected;
             */
            if(header.keys.contains(JwsCriticalHeaderParameterSpecification.NAME)) {
                throw IllegalStateException("The header parameter `${JwsCriticalHeaderParameterSpecification.NAME}` MUST be integrity protected.")
            }
        }
    }

    private val protectedHeaderDecoded: JsonObject?
        get() = protected?.let {
            joseCompliantSerializer.decodeFromString<JsonObject>(it.decodeToString())
        }

    val joseHeader: JsonObject
        get() = buildJsonObject {
            header?.forEach {
                put(it.key, it.value)
            }
            protectedHeaderDecoded?.forEach {
                put(it.key, it.value)
            }
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSignatureEntry

        if (protected != null) {
            if (other.protected == null) return false
            if (!protected.contentEquals(other.protected)) return false
        } else if (other.protected != null) return false
        if (header != other.header) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protected?.contentHashCode() ?: 0
        result = 31 * result + (header?.hashCode() ?: 0)
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

