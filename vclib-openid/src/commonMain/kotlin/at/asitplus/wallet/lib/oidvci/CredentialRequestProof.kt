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