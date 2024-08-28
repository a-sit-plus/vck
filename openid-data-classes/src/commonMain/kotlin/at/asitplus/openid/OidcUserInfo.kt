package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
 */
@Serializable
data class OidcUserInfo(
    @SerialName("sub")
    val subject: String,
    @SerialName("name")
    val name: String? = null,
    @SerialName("given_name")
    val givenName: String? = null,
    @SerialName("family_name")
    val familyName: String? = null,
    @SerialName("middle_name")
    val middleName: String? = null,
    @SerialName("nickname")
    val nickname: String? = null,
    @SerialName("preferred_username")
    val preferredUsername: String? = null,
    @SerialName("profile")
    val profile: String? = null,
    @SerialName("picture")
    val picture: String? = null,
    @SerialName("website")
    val website: String? = null,
    @SerialName("email")
    val email: String? = null,
    @SerialName("email_verified")
    val emailVerified: Boolean? = null,
    @SerialName("gender")
    val gender: String? = null,
    @SerialName("birthdate")
    val birthDate: String? = null,
    @SerialName("zoneinfo")
    val timezone: String? = null,
    @SerialName("locale")
    val locale: String? = null,
    @SerialName("phone_number")
    val phoneNumber: String? = null,
    @SerialName("phone_number_verified")
    val phoneNumberVerified: Boolean? = null,
    @SerialName("address")
    val address: OidcAddressClaim? = null,
    @SerialName("age_over_18")
    val ageOver18: Boolean? = null,
    @SerialName("updated_at")
    @Serializable(with = InstantLongSerializer::class)
    val updatedAt: Instant? = null,
)