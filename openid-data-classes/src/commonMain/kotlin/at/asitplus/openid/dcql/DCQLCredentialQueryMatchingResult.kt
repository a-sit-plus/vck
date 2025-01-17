package at.asitplus.openid.dcql

sealed interface DCQLCredentialQueryMatchingResult {
    data object AllClaimsMatchingResult : DCQLCredentialQueryMatchingResult

    class ClaimsQueryResults(
        val claimsQueryResults: List<DCQLClaimsQueryResult>,
    ) : DCQLCredentialQueryMatchingResult
}