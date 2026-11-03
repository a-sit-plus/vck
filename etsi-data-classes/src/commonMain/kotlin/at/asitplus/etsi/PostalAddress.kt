package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PostalAddress(
    /** Language tag identifying the language of the postal address (TS 119 612, 5.1.4; 5.3.5.1). */
    @SerialName(SerialNames.LANGUAGE_TAG)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val languageTag: Rfc5646LanguageTag,
    /** Street address of the postal contact point (TS 119 612, 5.3.5.1). */
    @SerialName(SerialNames.STREET_ADDRESS)
    val streetAddress: String,
    /**
     * Country code of the postal address, using the specified ETSI country-code conventions (TS 119 612, 5.1.5;
     * 5.3.5.1).
     */
    @SerialName(SerialNames.COUNTRY)
    val countryCode: EtsiCountryCode,
    /** Locality, such as the town or city, of the postal address (TS 119 612, 5.3.5.1). */
    @SerialName(SerialNames.LOCALITY)
    val locality: String? = null,
    /** State or province of the postal address (TS 119 612, 5.3.5.1). */
    @SerialName(SerialNames.STATE_OR_PROVINCE)
    val stateOrProvince: String? = null,
    /** Postal or ZIP code of the postal address (TS 119 612, 5.3.5.1). */
    @SerialName(SerialNames.POSTAL_CODE)
    val postalCode: String? = null,
) {
    object SerialNames {
        /** Wire member name `lang`. */
        const val LANGUAGE_TAG = "lang"
        /** Wire member name `StreetAddress`. */
        const val STREET_ADDRESS = "StreetAddress"
        /** Wire member name `Country`. */
        const val COUNTRY = "Country"
        /** Wire member name `Locality`. */
        const val LOCALITY = "Locality"
        /** Wire member name `StateOrProvince`. */
        const val STATE_OR_PROVINCE = "StateOrProvince"
        /** Wire member name `PostalCode`. */
        const val POSTAL_CODE = "PostalCode"
    }
}

