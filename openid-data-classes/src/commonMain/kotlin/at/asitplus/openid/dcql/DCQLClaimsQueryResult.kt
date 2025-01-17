package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeList

sealed interface DCQLClaimsQueryResult {
    class JsonClaimsQueryResult(
        val nodeList: NodeList
    ) : DCQLClaimsQueryResult

    class IsoMdocClaimsQueryResult(
        val namespace: String,
        val claimName: String,
        val claimValue: Any,
    ) : DCQLClaimsQueryResult
}