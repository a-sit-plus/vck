package at.asitplus.openid

import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC Data Model Bindings 1.0.0 section 7.1: REQUIRED
 * qesApprovalRequest transaction data; the `type` discriminator is required. At least one of [credentialId] or
 * [signatureQualifier] is required.
 */
@KeepGeneratedSerializer
@Serializable(with = QesApprovalRequestSerializer::class)
@SerialName(QesApprovalRequest.TYPE)
data class QesApprovalRequest(
    /**
     * OpenID4VP credential query: CONDITIONAL
     * Required when the transaction protocol identifies the approval credential through a credential query.
     */
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),

    /**

     * CSC Data Model Bindings 1.0.0 section 7.1: OPTIONAL
     * Locations of remote signing service providers (RFC 9396).
     */
    @SerialName("locations")
    val locations: List<String>? = null,

    /**

     * CSC Data Model Bindings 1.0.0 section 7.1: CONDITIONAL
     * Required when [signatureQualifier] is absent; at least one of these two identifiers is required.
     */
    @SerialName("credentialID")
    val credentialId: String? = null,

    /**

     * CSC Data Model Bindings 1.0.0 section 7.1: REQUIRED
     * Number of signatures to authorize; MUST be at least one.
     */
    @SerialName("numSignatures")
    val numSignatures: Int,

    /**

     * CSC Data Model Bindings 1.0.0 section 7.1: CONDITIONAL
     * Required when [credentialId] is absent; at least one of these two identifiers is required.
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**

     * ETSI TS 119 432 Annex B.6.2: REQUIRED
     * Documents covered by this approval.
     */
    @SerialName("documentDigests")
    val documentDigests: List<QesApprovalDocument>,

    /**

     * CSC Data Model Bindings 1.0.0 section 7.1: REQUIRED
     * Hash algorithm OID for qesApproval.
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier,

    /**

     * OpenID4VP Annex B.3.3.1: OPTIONAL
     * Hash algorithm identifiers for SD-JWT VC transaction-data binding.
     */
    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null,
) : TransactionData() {
    init {
        require(numSignatures >= 1) { "numSignatures must be at least 1" }
        require(documentDigests.isNotEmpty()) { "documentDigests must contain at least one document" }
        require(signatureQualifier != null || credentialId != null) {
            "signatureQualifier or credentialID must be present"
        }
    }

    companion object {
        const val TYPE = "https://cloudsignatureconsortium.org/2025/qes-approval"
    }
}
