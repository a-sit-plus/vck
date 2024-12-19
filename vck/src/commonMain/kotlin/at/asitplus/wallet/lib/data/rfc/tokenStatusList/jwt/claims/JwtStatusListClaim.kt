package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List
 * conforming to the rules outlined in Section 4.1.
 */
@Serializable
@JvmInline
value class JwtStatusListClaim(val statusList: StatusList) {
    object Specification {
        const val CLAIM_NAME = "status_list"
    }
}

