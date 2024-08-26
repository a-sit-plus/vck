@file:UseSerializers(UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import io.ktor.http.*
import io.ktor.util.reflect.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable
data class DocumentDigestEntry private constructor(
    val label: String,
    val hash: String? = null, // base64 encoded octet representation using "hashAlgorithmOID"
    val hashAlgorithmOID: String? = null,
    @SerialName("documentLocations_uri") //errorous in test vector - changed for test case
    val documentLocationUri: Url? = null,
    @SerialName("documentLocation_method")
    val documentLocationMethod: DocumentLocationMethod? = null,
    val dtbsr: String? = null,
    val dtbsrHashAlgorithmOID: String? = null,
) {
    /**
     * If in each of the following bullet points one of the mentioned parameters is
     * present, the other must be present:
     *  “hash” and “hashAlgorithmOID”
     *  “documentLocation_uri” and “documentLocation_method”
     *  “dtbsr” and “dtbsrHashAlgorithmOID”
     * In each of the following bullet points at least one of the mentioned
     * parameters must be present:
     *  “hash” or “dtbsr”
     */
    init {
        require(hash != null || dtbsr != null)
        require(hashAlgorithmOID iff hash)
        require(dtbsrHashAlgorithmOID iff dtbsr)
        require(documentLocationUri?.toString() iff hash)
        require(documentLocationMethod?.toString() iff documentLocationUri?.toString())
    }

    @Serializable
    @SerialName("documentLocation_method")
    data class DocumentLocationMethod private constructor(
        val method: Method,
        val oneTimePassword: String? = null,
    ) {
        /**
         * If “document_access_mode” is “OTP”, “oneTimePassword” must be
         * present.
         */
        init {
            require((oneTimePassword == null && method != Method.OTP)
                    || (oneTimePassword != null && method == Method.OTP))
        }

        /**
         * this is potentially a mistake in the draft spec vs test vector,
         * currently we need it to be a sealed class with polymorphic serialization to get the structure
         * method: {type: NAME}
         * sealed class would instead serialize to
         * method: NAME
         * which might be the corrected implementation in the next draft
         */
        @Serializable
        @SerialName("method")
        sealed class Method {
            @Serializable
            @SerialName("public")
            data object Public : Method()
            @Serializable
            @SerialName("otp")
            data object OTP : Method()
            @Serializable
            @SerialName("basic_auth")
            data object Basic : Method()
            @Serializable
            @SerialName("digest_auth")
            data object Digest : Method()
            @Serializable
            @SerialName("oauth_20")
            data object Oauth2 : Method()
        }

        companion object {
            fun create(method: Method, oneTimePassword: String?): KmmResult<DocumentLocationMethod> =
                runCatching {
                    DocumentLocationMethod(
                        method = method,
                        oneTimePassword = oneTimePassword
                    )
                }.wrap()
        }
    }

    companion object {
        /**
         * Safe way to construct the object as init throws
         */
        fun create(
            label: String,
            hash: String?,
            hashAlgorithmOID: String?,
            documentLocationUri: Url?,
            documentLocationMethod: DocumentLocationMethod?,
            dtbsr: String?,
            dtbsrHashAlgorithmOID: String?,
        ): KmmResult<DocumentDigestEntry> =
            kotlin.runCatching {
                DocumentDigestEntry(
                    label = label,
                    hash = hash,
                    hashAlgorithmOID = hashAlgorithmOID,
                    documentLocationUri = documentLocationUri,
                    documentLocationMethod = documentLocationMethod,
                    dtbsr = dtbsr,
                    dtbsrHashAlgorithmOID = dtbsrHashAlgorithmOID,
                )
            }.wrap()

    }
}

/**
 * Checks that either both strings are present or null
 */
private infix fun String?.iff(other: String?): Boolean =
    (this != null && other != null) or (this == null && other == null)


object UrlSerializer : KSerializer<Url> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UrlSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Url = Url(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Url) {
        encoder.encodeString(value.toString())
    }
}