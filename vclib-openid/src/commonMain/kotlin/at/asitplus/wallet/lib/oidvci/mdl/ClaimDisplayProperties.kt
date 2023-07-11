package at.asitplus.wallet.lib.oidvci.mdl

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClaimDisplayProperties(
    /**
     * OID4VCI:
     * OPTIONAL. String value of a display name for the claim.
     */
    @SerialName("name")
    val name: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL. String value that identifies language of this object represented as language tag values defined in BCP47 [RFC5646].
     */
    @SerialName("locale")
    val locale: String? = null,
)