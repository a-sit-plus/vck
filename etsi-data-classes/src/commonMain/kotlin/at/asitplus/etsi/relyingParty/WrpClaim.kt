package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C claim selector. EUDI TS5 registers paths only;
 * WRPRC authorization rejects [values] until value constraints can be evaluated.
 */
@Serializable
data class WrpClaim(
    /** Path to the claim within the credential (clause B.2.10). */
    @SerialName("path")
    val path: List<String>,

    /** Expected values of the claim, if constrained (clause B.2.10). */
    @SerialName("values")
    val values: List<String>? = null
)
