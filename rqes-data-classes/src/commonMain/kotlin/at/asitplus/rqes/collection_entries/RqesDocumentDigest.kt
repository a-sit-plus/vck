package at.asitplus.rqes.collection_entries

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@ConsistentCopyVisibility
@Serializable
data class RqesDocumentDigestEntry private constructor(
    /**
     * D3.1: UC Specification WP3: REQUIRED.
     * String containing a human-readable
     * description of the document to
     * be signed (SD). The Wallet MUST
     * show the label element in the
     * user interaction. It MUST be
     * UTF-8 encoded.
     */
    @SerialName("label")
    val label: String,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing the base64-encoded
     * octet-representation of applying
     * the algorithm from
     * [hashAlgorithmOid] to the octet-
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
     * If the [hash] property is not present this parameter MUST
     * NOT be present.
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * URL to the document
     * to be signed (SD); the parameter
     * [hash] MUST be the hash value
     * of the designated document.
     * If this parameter is present, the parameter
     * [documentLocationMethod] MUST be present.
     */
    @SerialName("documentLocation_uri")
    val documentLocationUri: String? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * An object with information how to access [documentLocationUri].
     * If the [documentLocationUri] property is not present, this
     * property MUST NOT be present
     */
    @SerialName("documentLocation_method")
    val documentLocationMethod: DocumentLocationMethod? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing data to be signed
     * representation as defined in CEN
     * EN 419241-1 and ETSI/TR 119
     * 001:2016 (as base64-encoded octet).
     * If this property is present,
     * the [dtbsrHashAlgorithmOid] MUST
     * be present.
     * One of the parameters [hash] and [dataToBeSignedRepresentation] MUST be
     * present. Both parameters [hash] and [dataToBeSignedRepresentation] MAY be
     * present.
     */
    @SerialName("DTBS/R")
    @Serializable(ByteArrayBase64Serializer::class)
    val dataToBeSignedRepresentation: ByteArray? = null,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * String containing the
     * OID of the hash algorithm used
     * to generate the hash listed in
     * [dataToBeSignedRepresentation]
     * If [dataToBeSignedRepresentation] property is not
     * present, this parameter MUST NOT be present.
     * NOTE: Usually this request does not contain enough
     * information to recreate the [dataToBeSignedRepresentation]. It should be considered
     * opaque for the Wallet.
     */
    @SerialName("DTBS/RHashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val dtbsrHashAlgorithmOid: ObjectIdentifier? = null,
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
        require(hashAlgorithmOid iff hash) {"If any is set both hashAlgorithmOid and hash must be set"}
        require(dtbsrHashAlgorithmOid iff dataToBeSignedRepresentation) {"If any is set both dtbsrHashAlgorithmOid and dataToBeSignedRepresentation must be set"}
        require(documentLocationMethod iff documentLocationUri) {"If any is set both documentLocationMethod and documentLocationUri must be set"}
        require(hash or dataToBeSignedRepresentation) {"Either hash or dataToBeSignedRepresentation must be set"}
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RqesDocumentDigestEntry

        if (label != other.label) return false
        if (hash != null) {
            if (other.hash == null) return false
            if (!hash.contentEquals(other.hash)) return false
        } else if (other.hash != null) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (documentLocationUri != other.documentLocationUri) return false
        if (documentLocationMethod != other.documentLocationMethod) return false
        if (dataToBeSignedRepresentation != null) {
            if (other.dataToBeSignedRepresentation == null) return false
            if (!dataToBeSignedRepresentation.contentEquals(other.dataToBeSignedRepresentation)) return false
        } else if (other.dataToBeSignedRepresentation != null) return false
        if (dtbsrHashAlgorithmOid != other.dtbsrHashAlgorithmOid) return false

        return true
    }

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + (hash?.contentHashCode() ?: 0)
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + (documentLocationUri?.hashCode() ?: 0)
        result = 31 * result + (documentLocationMethod?.hashCode() ?: 0)
        result = 31 * result + (dataToBeSignedRepresentation?.contentHashCode() ?: 0)
        result = 31 * result + (dtbsrHashAlgorithmOid?.hashCode() ?: 0)
        return result
    }

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * An object with
     * information how to access
     * [documentLocationUri].
     */
//    @Suppress("DEPRECATION")
    @Serializable
    @SerialName("documentLocation_method")
    data class DocumentLocationMethod(
        @SerialName("document_access_mode")
        val documentAccessMode: DocumentAccessMode,
        @SerialName("oneTimePassword")
        val oneTimePassword: String? = null,
    ) {
        init {
            if (documentAccessMode == DocumentAccessMode.OTP) require(!oneTimePassword.isNullOrEmpty())
            else require(oneTimePassword.isNullOrEmpty())
        }

        /**
         * Incompatible version of [at.asitplus.rqes.Method] due to presumably incomplete changes in draft
         */
        @Deprecated("Unify with [at.asitplus.rqes.Method] as soon as new draft allows")
        enum class DocumentAccessMode {
            @SerialName("public")
            PUBLIC,
            @SerialName("OTP")
            OTP,
            @SerialName("Basic_Auth")
            BASIC,
            @SerialName("Digest_Auth")
            DIGEST,
            @SerialName("OAuth_20")
            OAUTH2,
        }
    }

    companion object {
        /**
         * Safe way to construct the object as init throws
         */
        fun create(
            label: String,
            hash: ByteArray? = null,
            hashAlgorithmOID: ObjectIdentifier? = null,
            documentLocationUri: String? = null,
            documentLocationMethod: DocumentLocationMethod? = null,
            dtbsr: ByteArray? = null,
            dtbsrHashAlgorithmOID: ObjectIdentifier? = null,
        ): KmmResult<RqesDocumentDigestEntry> = catching {
            RqesDocumentDigestEntry(
                label = label,
                hash = hash,
                hashAlgorithmOid = hashAlgorithmOID,
                documentLocationUri = documentLocationUri,
                documentLocationMethod = documentLocationMethod,
                dataToBeSignedRepresentation = dtbsr,
                dtbsrHashAlgorithmOid = dtbsrHashAlgorithmOID,
            )
        }
    }
}

/**
 * Checks if either both strings are present or null
 */
internal infix fun Any?.iff(other: Any?): Boolean =
    (this != null && other != null) or (this == null && other == null)

/**
 * Checks if at least one Element is present
 */
internal infix fun Any?.or(other: Any?): Boolean =
    (this != null || other != null)