package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeList

sealed interface DCQLClaimsQueryResult {
    data class JsonResult(
        val nodeList: NodeList,
    ) : DCQLClaimsQueryResult

    /** [claimValue] is the JSON value of the data element, see [DCQLCredentialClaimStructure.IsoMdocStructure]. */
    data class IsoMdocResult(
        val namespace: String,
        val claimName: String,
        val claimValue: Any,
    ) : DCQLClaimsQueryResult
}