package at.asitplus.wallet.lib.data.rfc8392.cose

import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName

/**
 * TODO: this is probably defined in an RFC before 8392
 */
interface CoseHeaderParameterSpecification {
    companion object {}

    val cborName: CwtClaimName
    val cborLabel: CwtClaimKey

    fun toLabeledName() = "$cborName ($cborLabel)"
}