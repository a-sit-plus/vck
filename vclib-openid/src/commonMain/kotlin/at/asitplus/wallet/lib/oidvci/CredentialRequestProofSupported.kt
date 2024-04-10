package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProofSupported(
    /**
     * OID4VCI: REQUIRED. Array of case sensitive strings that identify the algorithms that the Issuer supports for
     * this proof type. The Wallet uses one of them to sign the proof. Algorithm names used are determined by the
     * key proof type and are defined in Section 7.2.1.
     */
    @SerialName("proof_signing_alg_values_supported")
    val supportedSigningAlgorithms: Collection<String>,
)