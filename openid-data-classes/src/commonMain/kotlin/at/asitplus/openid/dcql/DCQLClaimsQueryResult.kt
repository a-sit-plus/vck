package at.asitplus.openid.dcql

sealed interface DCQLClaimsQueryResult {
    /** [selectedClaims] are the claims the claims query selects, see [DCQLJsonClaimsQuery]. */
    data class JsonResult(
        val selectedClaims: List<DCQLSelectedClaim>,
    ) : DCQLClaimsQueryResult

    /** [claimValue] is the JSON value of the data element, see [DCQLCredentialClaimStructure.IsoMdocStructure]. */
    data class IsoMdocResult(
        val namespace: String,
        val claimName: String,
        val claimValue: Any,
    ) : DCQLClaimsQueryResult
}
