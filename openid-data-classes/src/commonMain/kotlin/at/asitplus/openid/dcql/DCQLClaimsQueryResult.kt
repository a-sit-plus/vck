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
    ) : DCQLClaimsQueryResult
}