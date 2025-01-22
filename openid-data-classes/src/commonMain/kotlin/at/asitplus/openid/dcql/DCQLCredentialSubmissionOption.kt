package at.asitplus.openid.dcql

data class DCQLCredentialSubmissionOption<Credential: Any>(
    val credential: Credential,
    val matchingResult: DCQLCredentialQueryMatchingResult,
)