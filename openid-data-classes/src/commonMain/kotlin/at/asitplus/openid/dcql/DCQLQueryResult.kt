package at.asitplus.openid.dcql

data class DCQLQueryResult<Credential: Any>(
    val credentialQueryMatches: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>,
    val satisfiableCredentialSetQueries: List<DCQLCredentialSetQuery>
)



