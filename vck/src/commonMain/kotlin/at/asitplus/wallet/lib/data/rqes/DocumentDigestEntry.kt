@file:UseSerializers(UrlSerializer::class)

package at.asitplus.wallet.lib.data.rqes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.wallet.lib.data.dif.UrlSerializer
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

@Serializable
data class DocumentDigestEntry private constructor(
    @SerialName("label")
    val label: String,
    /**
     * base64 encoded octet representation generated using hashAlgorithmOID
     */
    @SerialName("hash")
    val hash: @Serializable(ByteArrayBase64Serializer::class) ByteArray? = null,
    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOID: @Serializable(ObjectIdSerializer::class) ObjectIdentifier? = null,
    @SerialName("documentLocation_uri")
    val documentLocationUri: Url? = null,
    @SerialName("documentLocation_method")
    val documentLocationMethod: DocumentLocationMethod? = null,
    /**
     * base64 encoded octet representation generated using dtbsrAlgorithmOID
     */
    @SerialName("dtbsr")
    val dataToBeSignedRepresentation: @Serializable(ByteArrayBase64Serializer::class) ByteArray? = null,
    @SerialName("dtbsrHashAlgorithmOID")
    val dtbsrHashAlgorithmOID: @Serializable(ObjectIdSerializer::class) ObjectIdentifier? = null,
) {
    /**
     * If in each of the following bullet points one of the mentioned parameters is
     * present, the other must be present:
     * - [hash] and [hashAlgorithmOID]
     * - [documentLocation_uri] and [documentLocation_method]
     * - [dtbsr] and [dtbsrHashAlgorithmOID]
     * In each of the following bullet points at least one of the mentioned
     * parameters must be present:
     * - [hash] or [dtbsr]
     */
    init {
        require(hash != null || dataToBeSignedRepresentation != null)
        require(hashAlgorithmOID?.toString() iff hash?.toString())
        require(dtbsrHashAlgorithmOID?.toString() iff dataToBeSignedRepresentation?.toString())
        require(documentLocationUri?.toString() iff hash?.toString())
        require(documentLocationMethod?.toString() iff documentLocationUri?.toString())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DocumentDigestEntry

        if (label != other.label) return false
        if (hash != null) {
            if (other.hash == null) return false
            if (!hash.contentEquals(other.hash)) return false
        } else if (other.hash != null) return false
        if (hashAlgorithmOID != other.hashAlgorithmOID) return false
        if (documentLocationUri != other.documentLocationUri) return false
        if (documentLocationMethod != other.documentLocationMethod) return false
        if (dataToBeSignedRepresentation != null) {
            if (other.dataToBeSignedRepresentation == null) return false
            if (!dataToBeSignedRepresentation.contentEquals(other.dataToBeSignedRepresentation)) return false
        } else if (other.dataToBeSignedRepresentation != null) return false
        if (dtbsrHashAlgorithmOID != other.dtbsrHashAlgorithmOID) return false

        return true
    }

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + (hash?.contentHashCode() ?: 0)
        result = 31 * result + (hashAlgorithmOID?.hashCode() ?: 0)
        result = 31 * result + (documentLocationUri?.hashCode() ?: 0)
        result = 31 * result + (documentLocationMethod?.hashCode() ?: 0)
        result = 31 * result + (dataToBeSignedRepresentation?.contentHashCode() ?: 0)
        result = 31 * result + (dtbsrHashAlgorithmOID?.hashCode() ?: 0)
        return result
    }

    @Serializable
    @SerialName("documentLocation_method")
    data class DocumentLocationMethod private constructor(
        val method: Method,
        val oneTimePassword: String? = null,
    ) {
        /**
         * If [method] is `OTP`, [oneTimePassword] must be
         * present.
         */
        init {
            require(
                (oneTimePassword == null && method != Method.OTP)
                        || (oneTimePassword != null && method == Method.OTP)
            )
        }

        /**
         * this is potentially a mistake in the draft spec vs test vector,
         * currently we need it to be a sealed class with polymorphic serialization to get the structure
         * `method: {type: NAME}`
         * sealed class would instead serialize to
         * `method: NAME`
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
            hash: ByteArray?,
            hashAlgorithmOID: ObjectIdentifier?,
            documentLocationUri: Url?,
            documentLocationMethod: DocumentLocationMethod?,
            dtbsr: ByteArray?,
            dtbsrHashAlgorithmOID: ObjectIdentifier?,
        ): KmmResult<DocumentDigestEntry> =
            kotlin.runCatching {
                DocumentDigestEntry(
                    label = label,
                    hash = hash,
                    hashAlgorithmOID = hashAlgorithmOID,
                    documentLocationUri = documentLocationUri,
                    documentLocationMethod = documentLocationMethod,
                    dataToBeSignedRepresentation = dtbsr,
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
