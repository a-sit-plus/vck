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
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),
    @SerialName("locations")
    val locations: List<String>? = null,
    @SerialName("credentialID")
    val credentialId: String? = null,
    @SerialName("numSignatures")
    val numSignatures: Int,
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,
    @SerialName("documentDigests")
    val documentDigests: List<QesApprovalDocument>,
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier,
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