package at.asitplus.openid

import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** CSC Data Model Bindings 1.0.0 section 6.2.1, QES request transaction data. */
@Serializable
@SerialName(QesRequest.TYPE)
data class QesRequest(
    /** OID4VP credential query identifiers; omitted when the transaction-data protocol does not require them. */
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),

    /** The trust framework for the requested qualified signature. */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier,

    @SerialName("signatureRequests")
    val signatureRequests: List<QesSignatureRequest>,

    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null,
) : TransactionData() {
    companion object {
        const val TYPE = "https://cloudsignatureconsortium.org/2025/qes"
    }
}