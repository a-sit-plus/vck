package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeList

sealed interface DCQLClaimsQueryResult {
    class JsonResult(
        val nodeList: NodeList
    ) : DCQLClaimsQueryResult

    class IsoMdocResult(
        val namespace: String,
        val claimName: String,
        val claimValue: Any,
    ) : DCQLClaimsQueryResult
}