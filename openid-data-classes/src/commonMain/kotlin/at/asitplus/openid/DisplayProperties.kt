package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: OPTIONAL. A non-empty array of objects, where each object contains the display properties of the
 * supported Credential for a certain language.
 */
@Serializable
data class DisplayProperties(
    /**
     * OID4VCI: OPTIONAL. String value of a display name for the claim.
     */
    @SerialName("name")
    val name: String? = null,

    /**
     * OID4VCI: OPTIONAL. String value that identifies the language of this object represented as a language tag taken
     * from values defined in BCP47 (RFC5646). Multiple display objects MAY be included for separate languages. There
     * MUST be only one object for each language identifier.
     */
    @SerialName("locale")
    val locale: String? = null,

    /**
     * OID4VCI: OPTIONAL. Object with information about the logo of the Credential.
     */
    @SerialName("logo")
    val logo: DisplayLogoProperties? = null,

    /**
     * OID4VCI: OPTIONAL. String value of a description of the Credential.
     */
    @SerialName("description")
    val description: String? = null,

    /**
     * OID4VCI: OPTIONAL. String value of a background color of the Credential represented as numerical color values
     * defined in CSS Color Module Level 37.
     */
    @SerialName("background_color")
    val backgroundColor: String? = null,

    /**
     * OID4VCI: OPTIONAL. Object with information about the background image of the Credential.
     */
    @SerialName("background_image")
    val backgroundImage: DisplayLogoProperties? = null,

    /**
     * OID4VCI: OPTIONAL. String value of a text color of the Credential represented as numerical color values defined
     * in CSS Color Module Level 37
     */
    @SerialName("text_color")
    val textColor: String? = null,
)