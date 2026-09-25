package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C claim selector. EUDI TS5 registers paths only;
 * WRPRC authorization rejects [values] until value constraints can be evaluated.
 */
@Serializable
data class WrpClaim(
    @SerialName("path")
    val path: List<String>,

    @SerialName("values")
    val values: List<String>? = null
)
