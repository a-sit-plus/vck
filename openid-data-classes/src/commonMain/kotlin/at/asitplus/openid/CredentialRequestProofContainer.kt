package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProofContainer(
    /**
     * OID4VCI: e.g. `jwt`, or `ldp_vp`. See [at.asitplus.openid.OpenIdConstants.ProofType].
     */
    @SerialName("proof_type")
    val proofType: OpenIdConstants.ProofType,

    /**
     * OID4VCI: A JWT (RFC7519) is used as proof of possession. When [proofType] is `jwt`, a proof object MUST include
     * a `jwt` claim containing a JWT defined in Section 7.2.1.1.
     */
    @SerialName("jwt")
    val jwt: Set<String>? = null,
)