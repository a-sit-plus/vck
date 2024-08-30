package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: W3C VC: To express the specifics about the claim, the most deeply nested value MAY be an object that
 * includes the following parameters defined by this specification (other parameters MAY also be used).
 */
@Serializable
data class CredentialSubjectMetadataSingle(
    /**
     * OID4VCI: OPTIONAL. Boolean which when set to `true` indicates the claim MUST be present in the issued Credential.
     * If the mandatory property is omitted its default should be assumed to be false.
     */
    @SerialName("mandatory")
    val mandatory: Boolean? = null,

    /**
     * OID4VCI: OPTIONAL. String value determining type of value of the claim. A non-exhaustive list of valid values
     * defined by this specification are string, number, and image media types such as image/jpeg as defined in IANA
     * media type registry for images (https://www.iana.org/assignments/media-types/media-types.xhtml#image).
     */
    @SerialName("value_type")
    val valueType: String? = null,

    /**
     * OID4VCI: OPTIONAL. An array of objects, where each object contains display properties of a certain claim in the
     * Credential for a certain language.
     */
    @SerialName("display")
    val display: Set<DisplayProperties>? = null,

    )

