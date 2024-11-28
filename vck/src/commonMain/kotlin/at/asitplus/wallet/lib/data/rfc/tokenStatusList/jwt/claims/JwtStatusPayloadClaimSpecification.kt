package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.json.JsonObjectKey
import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlin.jvm.JvmInline

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 *  6.1. Status Claim
 *
 * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism to
 * retrieve status information about this Referenced Token. The claim contains members used to
 * reference to a status list as defined in this specification. Other members of the "status" object
 * may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1 of
 * [RFC7800] in which different authenticity confirmation methods can be included.
 *
 * The status (status) claim MUST specify a JSON Object that contains at least one reference to a
 * status mechanism.
 */
data object JwtStatusPayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "status"

    interface ClaimProvider<StatusType> {
        @SerialName(NAME)
        val status: StatusType?
    }

    val JwtPayloadClaimSpecification.Companion.status: JwtStatusPayloadClaimSpecification
        get() = JwtStatusPayloadClaimSpecification
}