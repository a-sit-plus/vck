package at.asitplus.openid

import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC Data Model Bindings 1.0.0 section 6.2.1: REQUIRED
 * QES request transaction data; the `type` discriminator is required.
 */
@Serializable
@SerialName(QesRequest.TYPE)
data class QesRequest(
    /**
     * OpenID4VP credential query: CONDITIONAL
     * Required when the transaction protocol identifies signing credentials through a credential query.
     */
    @SerialName("credential_ids")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    override val credentialIds: Set<String> = emptySet(),

    /**

     * CSC Data Model Bindings 1.0.0 section 6.2.1: CONDITIONAL
     * Required at this level; ETSI TS 119 432 Annex A supplies it on each signature request instead.
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    /**

     * CSC Data Model Bindings 1.0.0 section 6.2.1 / ETSI TS 119 432 Annex A.6.4: REQUIRED
     * Signature requests.
     */
    @SerialName("signatureRequests")
    val signatureRequests: List<QesSignatureRequest>,

    /**

     * OpenID4VP Annex B.3.3.1: OPTIONAL
     * Hash algorithm identifiers for SD-JWT VC transaction-data binding.
     */
    @SerialName("transaction_data_hashes_alg")
    override val transactionDataHashAlgorithms: Set<String>? = null,
) : TransactionData() {
    companion object {
        /**
         * CSC Data Model Bindings 1.0.0 section 6.2.1: REQUIRED
         * `type` discriminator value.
         */
        const val TYPE = "https://cloudsignatureconsortium.org/2025/qes"
    }
}
