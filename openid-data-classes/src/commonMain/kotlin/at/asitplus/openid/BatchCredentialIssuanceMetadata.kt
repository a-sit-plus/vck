package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class BatchCredentialIssuanceMetadata(
    /**
     * OID4VCI: REQUIRED. Integer value specifying the maximum array size for the proofs parameter in a
     * Credential Request.
     */
    @SerialName("batch_size")
    val batchSize: Int
)
