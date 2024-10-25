package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.SelectiveDisclosureItem

/**
 * Contains all claims that have been successfully reconstructed from an [SdJwtSigned]
 */
data class ReconstructedSdJwtClaims(
    val claims: Collection<SelectiveDisclosureItem>
)