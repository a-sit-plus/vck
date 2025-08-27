package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: OPTIONAL. Object with information about the logo of the Credential.
 */
@Serializable
data class DisplayLogoProperties(
    @SerialName("url")
    @Deprecated("Use `uri` instead", ReplaceWith("uri"))
    val url: String? = null,

    /**
     * OID4VCI: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential from
     * the Credential Issuer.
     */
    @SerialName("uri")
    val uri: String? = null,

    /**
     * OID4VCI: OPTIONAL. String value of the alternative text for the logo image.
     */
    @SerialName("alt_text")
    val altText: String? = null,
)