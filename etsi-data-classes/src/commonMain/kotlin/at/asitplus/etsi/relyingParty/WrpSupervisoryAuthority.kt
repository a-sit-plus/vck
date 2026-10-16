package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C supervisory-authority contact block.
 */
@Serializable
data class WrpSupervisoryAuthority(
    /** Email address of the competent data protection authority (Table 7). */
    @SerialName("email")
    val email: String? = null,

    /** Telephone number of the competent data protection authority (Table 7). */
    @SerialName("phone")
    val phone: String? = null,

    /** URL of the web form provided by the competent data protection authority (Table 7). */
    @SerialName("uri")
    val uri: String? = null,
)
