package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable

@Serializable
data class DCQLCredentialSubmissionOption<Credential: Any>(
    val credential: Credential,
    val matchingResult: DCQLCredentialQueryMatchingResult,
)