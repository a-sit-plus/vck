package at.asitplus.rqes.collection_entries

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Implements "Transaction Data entries" from [OpenID4VP Draft 23](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-transaction-data)
 */
@Serializable
sealed class TransactionData {

    /**
     * OID4VP: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used to
     * authorize this transaction. In Presentation Exchange, the string matches the `id` field in the Input Descriptor.
     * In the Digital Credentials Query Language, the string matches the id field in the Credential Query.
     * If there is more than one element in the array, the Wallet MUST use only one of the referenced Credentials for
     * transaction authorization.
     */
    // TODO Does this clash with WP3 definition of "credentialID"?
    abstract val credentialIds: Set<String>?

    /**
     * OID4VP: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used to
     * calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash
     * algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry
     * or a value defined in another specification and/or profile of this specification. If this parameter is not
     * present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support the
     * `sha-256` hash algorithm.
     */
    abstract val transactionDataHashAlgorithms: Set<String>?

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
         */
        @SerialName("signatureQualifier")
        val signatureQualifier: SignatureQualifier? = null,

        /**
         * CSC: OPTIONAL.
         * The unique identifier associated with the credential.
         */
        @SerialName("credentialID")
        val credentialID: String? = null,

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

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * An array composed of entries for every document to be signed (SD).
         * This applies for both cases, where a document is signed, or a digest is
         * signed. Every entry is composed of the following elements. Not all
         * entries need to be present in a particular request, but a wallet needs
         * to handle all of them if present.
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
    ) : TransactionData() {

        /**
         * Validation according to D3.1: UC Specification WP3
         */
        init {
            if (credentialID == null) {
                require(signatureQualifier != null)
            }
            if (signatureQualifier == null) {
                require(credentialID != null)
            }
        }

        companion object {
            /**
             * Safe way to construct the object as init throws
             */
            fun create(
                signatureQualifier: SignatureQualifier?,
                credentialId: String?,
                documentDigest: List<RqesDocumentDigestEntry>,
                processID: String?,
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

    /**
     * D3.1: UC Specification WP3:
     * Transaction data entry used to gather the user’s consent to the terms of
     * service of the Verifier (e.g. the QTSP)
     */
    @Serializable
    @SerialName("qcert_creation_acceptance")
    data class QCertCreationAcceptance(
        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * URL that points to a human-readable
         * terms of service document for the end
         * user that describes a contractual
         * relationship between the end-user and
         * the Qualified Trust Service Provider
         * The value of this field MUST
         * point to a document which is
         * accessible and displayable by the
         * Wallet.
         */
        @SerialName("QC_terms_conditions_uri")
        val qcTermsConditionsUri: String,

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * String containing the base64-encoded
         * octet-representation of applying the
         * algorithm from
         * [qcHashAlgorithmOid] to the octet-
         * representation of the document
         * referenced by [qcTermsConditionsUri]
         */
        @SerialName("QC_hash")
        @Serializable(ByteArrayBase64Serializer::class)
        val qcHash: ByteArray,

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * String containing the
         * OID of the hash algorithm used
         * to generate the hash listed in
         * [qcHash]
         */
        @SerialName("QC_hashAlgorithmOID")
        @Serializable(ObjectIdSerializer::class)
        val qcHashAlgorithmOid: ObjectIdentifier,

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
    ) : TransactionData() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as QCertCreationAcceptance

            if (qcTermsConditionsUri != other.qcTermsConditionsUri) return false
            if (!qcHash.contentEquals(other.qcHash)) return false
            if (qcHashAlgorithmOid != other.qcHashAlgorithmOid) return false
            if (credentialIds != other.credentialIds) return false
            if (transactionDataHashAlgorithms != other.transactionDataHashAlgorithms) return false

            return true
        }

        override fun hashCode(): Int {
            var result = qcTermsConditionsUri.hashCode()
            result = 31 * result + qcHash.contentHashCode()
            result = 31 * result + qcHashAlgorithmOid.hashCode()
            result = 31 * result + (credentialIds?.hashCode() ?: 0)
            result = 31 * result + (transactionDataHashAlgorithms?.hashCode() ?: 0)
            return result
        }
    }
}


