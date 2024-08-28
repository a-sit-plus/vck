package at.asitplus.openid

import at.asitplus.openid.OpenIdConstants
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestProof(
    /**
     * OID4VCI: e.g. `jwt`, or `cwt`, or `ldp_vp`. See [at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofType].
     */
    @SerialName("proof_type")
    val proofType: OpenIdConstants.ProofType,

    /**
     * OID4VCI: A JWT (RFC7519) is used as proof of possession. When [proofType] is `jwt`, a proof object MUST include
     * a `jwt` claim containing a JWT defined in Section 7.2.1.1.
     */
    @SerialName("jwt")
    val jwt: String? = null,

    /**
     * OID4VCI: A CWT (RFC8392) is used as proof of possession. When [proofType] is `cwt`, a proof object MUST include
     * a `cwt` claim containing a CWT defined in Section 7.2.1.3.
     */
    @SerialName("cwt")
    val cwt: String? = null,
)