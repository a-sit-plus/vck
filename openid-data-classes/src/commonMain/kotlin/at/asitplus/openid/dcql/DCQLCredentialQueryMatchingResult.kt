package at.asitplus.openid.dcql

sealed interface DCQLCredentialQueryMatchingResult {
    /**
     * OpenID4VP 1.0, section 6.4.1: for formats without selective disclosure,
     * absent `claims` requests the full credential because all claims are mandatory.
     *
     * Also the result for such a credential that satisfies present `claims`: it can only be presented as a whole, so
     * every claim of it is disclosed, not only the requested ones.
     */
    data object AllClaimsMatchingResult : DCQLCredentialQueryMatchingResult

    /**
     * OpenID4VP 1.0, section 6.4.1: for selectively disclosable credentials,
     * absent `claims` requests no selectively disclosable claims, only mandatory claims.
     */
    data object AllMandatoryClaimsMatchingResult : DCQLCredentialQueryMatchingResult

    /**
     * OpenID4VP 1.0, section 6.4.1: present `claims` requests the listed claims,
     * optionally constrained by `claim_sets`, of a selectively disclosable credential.
     */
    data class ClaimsQueryResults(
        val claimsQueryResults: List<DCQLClaimsQueryResult>,
    ) : DCQLCredentialQueryMatchingResult
}
