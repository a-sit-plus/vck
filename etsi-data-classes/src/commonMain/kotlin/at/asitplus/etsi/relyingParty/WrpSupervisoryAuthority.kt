package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C supervisory-authority contact block.
 */
@Serializable
data class WrpSupervisoryAuthority(
    @SerialName("email")
    val email: String? = null,

    @SerialName("phone")
    val phone: String? = null,

    @SerialName("uri")
    val uri: String? = null,
)
