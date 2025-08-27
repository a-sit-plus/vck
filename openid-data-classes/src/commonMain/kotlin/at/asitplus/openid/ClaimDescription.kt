package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClaimDescription(
    /**
     * OID4VCI: REQUIRED. The value MUST be a non-empty array representing a claims path pointer that specifies the path
     * to a claim within the credential, as defined in Appendix C.
     */
    @SerialName("path")
    val path: List<String>,

    /**
     * OID4VCI: Issuer Metadata:
     * OPTIONAL. Boolean which, when set to `true`, indicates that the Credential Issuer will always include this claim
     * in the issued Credential. If set to `false`, the claim is not included in the issued Credential if the wallet did
     * not request the inclusion of the claim, and/or if the Credential Issuer chose to not include the claim. If the
     * mandatory parameter is omitted, the default value is false.
     *
     * OID4VCI: Authorization Details:
     * OPTIONAL. Boolean which, when set to `true`, indicates that the Wallet will only accept a Credential that
     * includes this claim. If set to `false`, the claim is not required to be included in the Credential. If the
     * mandatory parameter is omitted, the default value is `false`.
     */
    @SerialName("mandatory")
    val mandatory: Boolean? = null,

    /**
     * OID4VCI: Issuer Metadata:
     * OPTIONAL. A non-empty array of objects, where each object contains display properties of a certain claim in the
     * Credential for a certain language.
     */
    @SerialName("display")
    val display: Set<DisplayProperties>? = null
)