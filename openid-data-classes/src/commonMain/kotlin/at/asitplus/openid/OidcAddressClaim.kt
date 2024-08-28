package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
 */
@Serializable
data class OidcAddressClaim(
    @SerialName("formatted")
    val formatted: String? = null,
    @SerialName("street_address")
    val street: String? = null,
    @SerialName("locality")
    val locality: String? = null,
    @SerialName("region")
    val region: String? = null,
    @SerialName("postal_code")
    val postalCode: String? = null,
    @SerialName("country")
    val country: String? = null,
)