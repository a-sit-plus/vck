package at.asitplus.openid

import at.asitplus.dif.FormatContainerJwt
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VP: An object containing a list of name/value pairs, where the name is a Credential Format Identifier and the
 * value defines format-specific parameters that a Wallet supports. For specific values that can be used, see
 * Appendix B. Deployments can extend the formats supported, provided Issuers, Holders and Verifiers all understand the
 * new format.
 */
@Serializable
data class VpFormatsSupported(
    /** See [CredentialFormatEnum.JWT_VC]. */
    @SerialName("jwt_vc_json")
    val vcJwt: SupportedAlgorithmsContainerJwt? = null,

    /** See [CredentialFormatEnum.DC_SD_JWT]. */
    @SerialName("dc+sd-jwt")
    val dcSdJwt: SupportedAlgorithmsContainerSdJwt? = null,

    /** See [CredentialFormatEnum.MSO_MDOC]. */
    @SerialName("mso_mdoc")
    val msoMdoc: SupportedAlgorithmsContainerIso? = null,
)

