package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive

@Deprecated("Interface was removed", ReplaceWith("at.asitplus.openid.TransactionData"))
interface TransactionData


/**
 * D3.1: UC Specification WP3:
 * Transaction data entry used to gather the user’s consent to the terms of
 * service of the Verifier (e.g. the QTSP)
 */
@Serializable
@SerialName("qcert_creation_acceptance")
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.openid.QCertCreationAcceptance"))
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
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val qcHashAlgorithmOid: ObjectIdentifier,

    /**
     * OID4VP: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used
     * to authorize this transaction. In Presentation Exchange, the string matches the `id` field in the Input
     * Descriptor. In the Digital Credentials Query Language, the string matches the id field in the Credential
     * Query. If there is more than one element in the array, the Wallet MUST use only one of the referenced
     * Credentials for transaction authorization.
     */
    @SerialName("credential_ids")
     val credentialIds: Set<String>? = null,

    /**
     * OID4VP: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used
     * to calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash
     * algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry
     * or a value defined in another specification and/or profile of this specification. If this parameter is not
     * present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support
     * the `sha-256` hash algorithm.
     */
    @SerialName("transaction_data_hashes_alg")
     val transactionDataHashAlgorithms: Set<String>? = null,

    ) : TransactionData {

    @Suppress("DEPRECATION")
     fun toBase64UrlJsonString(): JsonPrimitive =
        rdcJsonSerializer.parseToJsonElement(
            rdcJsonSerializer.encodeToString(
                at.asitplus.rqes.serializers.DeprecatedBase64URLTransactionDataSerializer,
                this
            )
        ) as JsonPrimitive
}


