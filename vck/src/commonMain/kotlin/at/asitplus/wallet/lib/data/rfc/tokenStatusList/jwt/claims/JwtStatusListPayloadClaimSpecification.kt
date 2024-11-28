package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import kotlinx.serialization.SerialName

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List conforming to the rules outlined in Section 4.1.
 */
data object JwtStatusListPayloadClaimSpecification : JwtPayloadClaimSpecification{
    const val NAME = "status_list"

    interface ClaimProvider {
        @SerialName(NAME)
        @Suppress("PropertyName") // intended specification name to prevent collisions
        val status_list: StatusList?
    }

    val JwtPayloadClaimSpecification.Companion.status: JwtStatusListPayloadClaimSpecification
        get() = JwtStatusListPayloadClaimSpecification
}