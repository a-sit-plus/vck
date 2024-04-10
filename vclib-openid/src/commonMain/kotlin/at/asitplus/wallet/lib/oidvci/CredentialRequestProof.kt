package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProof(
    /**
     * OID4VCI: e.g. `jwt`, or `cwt`, or `ldp_vp`.
     */
    @SerialName("proof_type")
    val proofType: String,

    /**
     * See OID4VCI Proof Types for contents.
     */
    @SerialName("proof")
    val proof: String,
)