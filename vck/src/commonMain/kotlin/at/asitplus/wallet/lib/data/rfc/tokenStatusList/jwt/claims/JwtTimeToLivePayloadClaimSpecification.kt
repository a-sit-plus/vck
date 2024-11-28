package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.JwtTimeToLive
import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import kotlinx.serialization.SerialName

/**
 * source: https://www.rfc-editor.org/rfc/rfc7519
 *
 * OPTIONAL.
 * The ttl (time to live) claim, if present, MUST specify the maximum amount of time,
 * in seconds, that the Status List Token can be cached by a consumer before a fresh
 * copy SHOULD be retrieved.
 * The value of the claim MUST be a positive number encoded in JSON as a number.
 */
data object JwtTimeToLivePayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "ttl"

    interface ClaimProvider {
        @SerialName(NAME)
        val ttl: JwtTimeToLive?
    }

    val JwtPayloadClaimSpecification.Companion.ttl: JwtTimeToLivePayloadClaimSpecification
        get() = JwtTimeToLivePayloadClaimSpecification
}