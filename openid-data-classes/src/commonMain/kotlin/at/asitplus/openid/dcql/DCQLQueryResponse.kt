package at.asitplus.openid.dcql

data class DCQLQueryResponse<DCQLCredentialQueryResponse: Any>(
    val submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialQueryResponse>>,
)

