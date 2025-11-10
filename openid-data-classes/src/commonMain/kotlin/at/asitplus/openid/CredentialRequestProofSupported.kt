package at.asitplus.openid

import at.asitplus.signum.indispensable.SignatureAlgorithm
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
    val supportedSigningAlgorithms: Collection<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Object that describes the requirement for key attestations as described in Appendix D,
     * which the Credential Issuer expects the Wallet to send within the [CredentialRequestProofContainer].
     * If the Credential Issuer does not require a key attestation, this parameter MUST NOT be present in the metadata.
     */
    @SerialName("key_attestations_required")
    val keyAttestationRequired: KeyAttestationRequired? = null,
) {
    val supportedSigningAlgorithmsParsed: Set<SignatureAlgorithm>?
        get() = supportedSigningAlgorithms?.mapNotNull {
            it.toIntOrNull()?.toCoseAlgorithm()?.toSignatureAlgorithm()
                ?: it.toJwsAlgorithm()?.toSignatureAlgorithm()
        }?.toSet()

}