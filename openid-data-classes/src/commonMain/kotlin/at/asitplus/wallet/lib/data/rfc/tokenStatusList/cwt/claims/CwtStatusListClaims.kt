package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 *  5.2. Status List Token in CWT Format
 * The status list claim MUST specify the Status List conforming to the rules outlined in Section 4.2.
 */
@Serializable
@JvmInline
value class CwtStatusListClaim(val statusList: StatusList) {
    data object Specification {
        const val CLAIM_NAME = "status_list"
        const val CLAIM_KEY = 65533L
    }
}

/**
 * specification: ISO18013-5
 * Conforming to the rules defined in 12.3.6
 */
@Serializable
@JvmInline
value class CwtIdentifierListClaim(val identifierList: IdentifierList) {
    data object Specification {
        const val CLAIM_NAME = "identifier_list"
        const val CLAIM_KEY = 65530L
    }
}