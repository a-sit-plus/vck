package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProof(
    /**
     * OID4VCI:
     * e.g. `jwt`
     */
    @SerialName("proof_type")
    val proofType: String,

    /**
     * See OID4VCI Proof Type "JWT"
     */
    @SerialName("jwt")
    val jwt: String
)