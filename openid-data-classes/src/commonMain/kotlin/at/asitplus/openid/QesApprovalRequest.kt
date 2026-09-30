package at.asitplus.openid

import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 7.1, with documentInfo/reference alternatives. */
@Serializable
@SerialName(QesApprovalRequest.TYPE)
data class QesApprovalRequest(
    /** OID4VP: Credential-query identifiers for the credential used to authorize this transaction. */
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),

    /** CSC Data Model Bindings 7.1: Optional locations associated with the approval request. */
    @SerialName("locations")
    val locations: List<String>? = null,

    /** CSC Data Model Bindings 7.1: Identifier of the signing credential in the CSC service, when supplied. */
    @SerialName("credentialID")
    val credentialId: String? = null,

    /** CSC Data Model Bindings 7.1: Number of signatures the user is asked to authorize; at least one. */
    @SerialName("numSignatures")
    val numSignatures: Int,

    /** CSC Data Model Bindings 7.1: Signature trust framework; required when [credentialId] is absent. */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /** TS 119 432 Annex B.6.2: Documents covered by this approval, represented by documentInfo or documentReference. */
    @SerialName("documentDigests")
    val documentDigests: List<QesApprovalDocument>,

    /** CSC Data Model Bindings 7.1: Hash algorithm OID for qesApproval over the exact UTF-8 JSON request bytes. */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier,

    /** OID4VP Annex B.3.3.1: Hash algorithms for binding this transaction into an SD-JWT VC Key Binding JWT. */
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
