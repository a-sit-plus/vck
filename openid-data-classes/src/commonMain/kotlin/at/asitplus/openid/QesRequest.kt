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
    /** OID4VP: Credential-query identifiers; omitted when the transaction-data protocol does not require them. */
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),

    /** TS 119 432 Annex A.6.4: Trust framework for the requested signature, such as `eu_eidas_qes`. */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier,

    /** CSC Data Model Bindings 6.2.1 / TS 119 432 Annex A.6.4: Documents and signature options for this QES transaction. */
    @SerialName("signatureRequests")
    val signatureRequests: List<QesSignatureRequest>,

    /** OID4VP Annex B.3.3.1: Hash algorithms for binding this transaction into an SD-JWT VC Key Binding JWT. */
    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null,
) : TransactionData() {
    companion object {
        const val TYPE = "https://cloudsignatureconsortium.org/2025/qes"
    }
}
