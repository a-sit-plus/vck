package at.asitplus.rqes.collection_entries

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TransactionData
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * D3.1: UC Specification WP3:
 * Transaction data entry used to authorize a qualified electronic signature
 */
@ConsistentCopyVisibility
@Serializable
@SerialName("qes_authorization")
data class QesAuthorization private constructor(
    /**
     * CSC: OPTIONAL.
     * Identifier of the signature type to be created. A set of such identifiers
     * is defined in (CSC-API) section 11.11.
     * D3.1: UC Specification WP3:
     * MUST be present when [credentialID] is not present.
     * Both [signatureQualifier] and [credentialID] values MAY be present.
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**
     * CSC: OPTIONAL.
     * The unique identifier associated with the credential.
     * D3.1: UC Specification WP3:
     * MUST be present when [signatureQualifier] parameter is not present.
     * Both [signatureQualifier] and [credentialID] values MAY be present.
     */
    @SerialName("credentialID")
    val credentialID: String? = null,

    /**
     * D3.1: UC Specification WP3: REQUIRED.
     * An array composed of entries for every document to be signed (SD).
     * This applies for both cases, where a document is signed, or a digest is
     * signed.
     */
    @SerialName("documentDigests")
    val documentDigests: List<RqesDocumentDigestEntry>,

    /**
     * D3.1: UC Specification WP3: OPTIONAL.
     * An opaque value used by the QTSP to
     * internally link the transaction to this
     * request. The parameter is not supposed
     * to contain a human-readable value.
     */
    @SerialName("processID")
    val processID: String? = null,
) : TransactionData {

    @SerialName("credential_ids")
    override val credentialIds: Set<String>? = null
    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null

    /**
     * Validation according to D3.1: UC Specification WP3
     */
    init {
        require(credentialID or signatureQualifier) { "Either credentialID or signatureQualifier must be set" }
    }

    companion object {
        /**
         * Safe way to construct the object as init throws
         */
        fun create(
            documentDigest: List<RqesDocumentDigestEntry>,
            signatureQualifier: SignatureQualifier? = null,
            credentialId: String? = null,
            processID: String? = null,
        ): KmmResult<TransactionData> = runCatching {
            QesAuthorization(
                signatureQualifier = signatureQualifier,
                credentialID = credentialId,
                documentDigests = documentDigest,
                processID = processID,
            )
        }.wrap()
    }
}
