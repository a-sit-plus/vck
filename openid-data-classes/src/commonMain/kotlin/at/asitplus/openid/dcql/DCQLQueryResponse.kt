package at.asitplus.openid.dcql

data class DCQLQueryResponse(
    val submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialQueryResponse>>,
)

