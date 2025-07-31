package at.asitplus.rqes.collection_entries

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TransactionData
import at.asitplus.rqes.rdcJsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive

/**
 * D3.1: UC Specification WP3:
 * Transaction data entry used to authorize a qualified electronic signature
 */
@Serializable
@SerialName("qes_authorization")
data class QesAuthorization(
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

    /**
     * OID4VP: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used
     * to authorize this transaction. In Presentation Exchange, the string matches the `id` field in the Input
     * Descriptor. In the Digital Credentials Query Language, the string matches the id field in the Credential
     * Query. If there is more than one element in the array, the Wallet MUST use only one of the referenced
     * Credentials for transaction authorization.
     */
    @SerialName("credential_ids")
    override val credentialIds: Set<String>? = null,

    /**
     * OID4VP: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used
     * to calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash
     * algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry
     * or a value defined in another specification and/or profile of this specification. If this parameter is not
     * present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support
     * the `sha-256` hash algorithm.
     */
    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null,

    ) : TransactionData {

    @Suppress("DEPRECATION")
    override fun toBase64UrlJsonString(): JsonPrimitive =
        rdcJsonSerializer.parseToJsonElement(
            rdcJsonSerializer.encodeToString(
                at.asitplus.rqes.serializers.DeprecatedBase64URLTransactionDataSerializer,
                this
            )
        ) as JsonPrimitive

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
            credentialIds: Set<String>? = null,
            transactionDataHashAlgorithms: Set<String>? = null,
        ): KmmResult<TransactionData> = catching {
            QesAuthorization(
                signatureQualifier = signatureQualifier,
                credentialID = credentialId,
                credentialIds = credentialIds,
                transactionDataHashAlgorithms = transactionDataHashAlgorithms,
                documentDigests = documentDigest,
                processID = processID,
            )
        }
    }
}
