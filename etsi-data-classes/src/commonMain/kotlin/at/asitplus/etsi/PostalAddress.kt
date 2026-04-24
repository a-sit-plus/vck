package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PostalAddress(
    @SerialName(SerialNames.LANGUAGE_TAG)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val languageTag: Rfc5646LanguageTag,
    @SerialName(SerialNames.STREET_ADDRESS)
    val streetAddress: String,
    @SerialName(SerialNames.COUNTRY)
    val countryCode: EtsiCountryCode,
    @SerialName(SerialNames.LOCALITY)
    val locality: String? = null,
    @SerialName(SerialNames.STATE_OR_PROVINCE)
    val stateOrProvince: String? = null,
    @SerialName(SerialNames.POSTAL_CODE)
    val postalCode: String? = null,
) {
    object SerialNames {
        const val LANGUAGE_TAG = "lang"
        const val STREET_ADDRESS = "StreetAddress"
        const val COUNTRY = "Country"
        const val LOCALITY = "Locality"
        const val STATE_OR_PROVINCE = "StateOrProvince"
        const val POSTAL_CODE = "PostalCode"
    }
}

