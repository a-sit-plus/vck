package at.asitplus.openid.dcql

import kotlinx.serialization.json.JsonElement

/**
 * A claim selected by processing a claims path pointer, see [DCQLClaimsPathPointer.query].
 *
 * [path] is the concrete position of the claim in the credential: a claims path pointer with names and indices only,
 * as OpenID4VP 1.0, 7.1 forms one "to address a particular claim within an object" or "an element within an array".
 */
data class DCQLSelectedClaim(
    val path: DCQLClaimsPathPointer,
    val value: JsonElement,
)
