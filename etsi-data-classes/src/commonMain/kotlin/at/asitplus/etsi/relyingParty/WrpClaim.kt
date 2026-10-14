package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C claim selector. EUDI TS5 registers paths only;
 * WRPRC authorization rejects [values] until value constraints can be evaluated.
 */
@Serializable
data class WrpClaim(
    /**
     * Path pointer to the claim within the credential (clause B.2.10), following the claims path pointer of
     * OpenID4VP, see [WrpClaimPathSegment].
     */
    @SerialName("path")
    val path: List<WrpClaimPathSegment>,

    /** Expected values of the claim, if constrained (clause B.2.10). */
    @SerialName("values")
    val values: List<WrpClaimValue>? = null
) {
    companion object {
        /** A claim selected by the names of its path, e.g. a namespace and an element identifier of ISO mdoc. */
        fun named(vararg names: String) = WrpClaim(names.map { WrpClaimPathSegment.Name(it) })
    }
}
