package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName

/**
 * [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
 */
data class OidcUserInfo(
    @SerialName("given_name")
    val givenName: String,
    @SerialName("family_name")
    val familyName: String,
    @SerialName("sub")
    val subject: String,
    @SerialName("email")
    val email: String? = null,
    @SerialName("address")
    val address: OidcAddressClaim? = null,
    @SerialName("birthdate")
    val birthDate: String? = null,
    @SerialName("gender")
    val gender: String? = null,
    @SerialName("age_over_18")
    val ageOver18: Boolean? = null,
    @SerialName("picture")
    val picture: String? = null,
)