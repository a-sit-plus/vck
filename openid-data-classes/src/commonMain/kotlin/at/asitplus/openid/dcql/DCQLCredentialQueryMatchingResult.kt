package at.asitplus.openid.dcql

sealed interface DCQLCredentialQueryMatchingResult {
    data object AllClaimsMatchingResult : DCQLCredentialQueryMatchingResult

    data class ClaimsQueryResults(
        val claimsQueryResults: List<DCQLClaimsQueryResult>,
    ) : DCQLCredentialQueryMatchingResult
}