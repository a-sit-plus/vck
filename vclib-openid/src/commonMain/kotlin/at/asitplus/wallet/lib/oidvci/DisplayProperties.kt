package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for a
 * certain language.
 */
@Serializable
data class DisplayProperties(
    /**
     * OID4VCI: OPTIONAL. String value of a display name for the claim.
     */
    @SerialName("name")
    val name: String? = null,

    /**
     * OID4VCI: OPTIONAL. String value that identifies language of this object represented as language tag values
     * defined in BCP47 (RFC5646). There MUST be only one object with the same language identifier.
     */
    @SerialName("locale")
    val locale: String? = null,
)