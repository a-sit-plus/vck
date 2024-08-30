@file:UseSerializers(UrlSerializer::class)

package at.asitplus.dif.rqes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

@Serializable
data class DocumentDigestEntry private constructor(
    /**
     * D3.1: UC Specification WP3: REQUIRED.
     * String containing a human-readable
     * description of the document to
     * be signed (SD). The Wallet MUST
     * show the label element in the
     * user interaction. It MUST be UTF-
     * 8 encoded.
     */
    @SerialName("label")
    val label: String,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing the base64-encoded
     * octet-representation of applying
     * the algorithm from
     * [hashAlgorithmOID] to the octet-
     * representation of the document
     * to be signed (SD).
     */
    @SerialName("hash")
    @Serializable(ByteArrayBase64Serializer::class)
    val hash: ByteArray? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing the OID of the
     * hash algorithm used to generate
     * the hash listed in the [hash].
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(ObjectIdSerializer::class)
    val hashAlgorithmOID: ObjectIdentifier? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * URL to the document
     * to be signed (SD); the parameter
     * [hash] MUST be the hash value
     * of the designated document.
     */
    @SerialName("documentLocation_uri")
    val documentLocationUri: Url? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * An object with
     * information how to access
     * [documentLocationUri].
     */
    @SerialName("documentLocation_method")
    val documentLocationMethod: DocumentLocationMethod? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing data to be signed
     * representation as defined in CEN
     * EN 419241-1 and ETSI/TR 119
     * 001:2016 (as base64-encoded octet).
     */
    @SerialName("dtbsr")
    @Serializable(ByteArrayBase64Serializer::class)
    val dataToBeSignedRepresentation: ByteArray? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing the
     * OID of the hash algorithm used
     * to generate the hash listed in
     * [dataToBeSignedRepresentation]
     */
    @SerialName("dtbsrHashAlgorithmOID")
    @Serializable(ObjectIdSerializer::class)
    val dtbsrHashAlgorithmOID: ObjectIdentifier? = null,
) {
    /**
     * D3.1: UC Specification WP3:
     * If in each of the following bullet points one of the mentioned parameters is
     * present, the other must be present:
     * - [hash] and [hashAlgorithmOID]
     * - [documentLocationUri] and [documentLocationMethod]
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

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * An object with
     * information how to access
     * [documentLocationUri].
     */
    @Serializable
    @SerialName("documentLocation_method")
    data class DocumentLocationMethod private constructor(
        val method: Method,
        val oneTimePassword: String? = null,
    ) {
        /**
         * D3.1: UC Specification WP3:
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
         * After D3.1: UC Specification WP3.
         * However, this class is potentially a mistake in the draft spec vs test vector,
         * currently we need it to be a sealed class with polymorphic serialization to get the structure
         * `method: {type: NAME}`
         * sealed class would instead serialize to
         * `method: NAME`
         * which might be the corrected implementation in the next draft.
         *
         * The method describes the restrictions/way of accessing a document
         */
        @Serializable
        @SerialName("method")
        sealed class Method {
            /**
             * D3.1: UC Specification WP3:
             * The document corresponding to the parameter [hash] can be
             * fetched from [documentLocationUri] with a https-request
             * without further restrictions.
             */
            @Serializable
            @SerialName("public")
            data object Public : Method()

            /**
             * D3.1: UC Specification WP3:
             * The wallet displays the parameter [oneTimePassword] to the
             * user. A webclient accessing the uri offers a way for the user to
             * input the shown value and only then allows to fetch the
             * document corresponding to [hash].
             */
            @Serializable
            @SerialName("otp")
            data object OTP : Method()

            /**
             * D3.1: UC Specification WP3:
             * The wallet fetches the document from
             * [documentLocationUri]. The document should be fetched
             * using the ‘Basic’ HTTP Authentication Scheme (RFC 7617).
             */
            @Serializable
            @SerialName("basic_auth")
            data object Basic : Method()

            /**
             * D3.1: UC Specification WP3:
             * The wallet fetches the document from
             * [documentLocationUri]. The document should be fetched
             * using the ‘Digest’ HTTP Authentication Scheme (RFC 7616).
             */
            @Serializable
            @SerialName("digest_auth")
            data object Digest : Method()

            /**
             * D3.1: UC Specification WP3:
             * The wallet fetches the document from
             * [documentLocationUri]. The document should be fetched
             * using the ‘OAuth 2.0’ Authentication Framework (RFC6749
             * and RFC8252).
             */
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
