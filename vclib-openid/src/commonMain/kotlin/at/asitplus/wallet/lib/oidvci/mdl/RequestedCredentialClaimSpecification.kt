package at.asitplus.wallet.lib.oidvci.mdl

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class RequestedCredentialClaimSpecification(

    /**
     * OID4VCI:
     * Boolean which when set to true indicates the claim MUST be present in the issued Credential.
     * If the mandatory property is omitted its default should be assumed to be false.
     */
    @SerialName("mandatory")
    val mandatory: Boolean? = null,

    /**
     * OID4VCI:
     * OPTIONAL. String value determining type of value of the claim.
     *
     * A non-exhaustive list of valid values defined by this specification are string, number,
     * and image media types such as image/jpeg as defined in IANA media type registry for images
     * (https://www.iana.org/assignments/media-types/media-types.xhtml#image).
     */
    @SerialName("value_type")
    val valueType: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL. An array of objects, where each object contains display properties
     * of a certain claim in the Credential for a certain language.
     * There MUST be only one object with the same language identifier.
     */
    @SerialName("display")
    val display: ClaimDisplayProperties? = null,
)