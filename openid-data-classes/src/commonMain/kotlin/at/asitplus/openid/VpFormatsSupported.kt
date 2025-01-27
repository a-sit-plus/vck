package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VP: An object containing a list of key value pairs, where the key is a string identifying a Credential format
 * supported by the Wallet. Valid Credential format identifier values are defined in Annex E of OpenID.VCI.
 * Other values may be used when defined in the profiles of this specification.
 */
@Serializable
data class VpFormatsSupported(
    /**
     * See [CredentialFormatEnum.JWT_VC]
     */
    @SerialName("jwt_vc_json")
    val vcJwt: SupportedAlgorithmsContainer? = null,

    /**
     * See [CredentialFormatEnum.JWT_VC_JSON_LD]
     */
    @SerialName("jwt_vc_json-ld")
    val vcJsonLd: SupportedAlgorithmsContainer? = null,

    /**
     * See [CredentialFormatEnum.VC_SD_JWT]
     */
    @Deprecated("Deprecated in SD-JWT VC since draft 06", replaceWith = ReplaceWith("dcSdJwt"))
    @SerialName("vc+sd-jwt")
    val vcSdJwt: SupportedAlgorithmsContainer? = null,

    /**
     * See [CredentialFormatEnum.DC_SD_JWT]
     */
    @SerialName("dc+sd-jwt")
    val dcSdJwt: SupportedAlgorithmsContainer? = null,

    /**
     * See [CredentialFormatEnum.JSON_LD]
     */
    @SerialName("ldp_vc")
    val jsonLinkedData: SupportedAlgorithmsContainer? = null,

    /**
     * See [CredentialFormatEnum.MSO_MDOC]
     */
    @SerialName("mso_mdoc")
    val msoMdoc: SupportedAlgorithmsContainer? = null,
)

