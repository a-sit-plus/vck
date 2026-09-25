package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C credential descriptor.
 */
@Serializable
data class WrpCredential(
    @SerialName("format")
    val format: String,

    @SerialName("meta")
    val meta: WrpCredentialMeta,

    @SerialName("claim")
    val claim: List<WrpClaim> = emptyList()
)
