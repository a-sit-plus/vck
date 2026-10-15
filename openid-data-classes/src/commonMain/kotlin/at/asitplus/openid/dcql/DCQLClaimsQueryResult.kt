package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeList

sealed interface DCQLClaimsQueryResult {
    data class JsonResult(
        val nodeList: NodeList,
    ) : DCQLClaimsQueryResult

    data class IsoMdocResult(
        val namespace: String,
        val claimName: String,
        val claimValue: Any,
        /** The identifier the verifier asked for, when 7.2.5 resolved it to a different [claimName]. */
        val requestedClaimName: String? = null,
    ) : DCQLClaimsQueryResult
}