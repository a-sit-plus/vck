package at.asitplus.wallet.lib.openid

import at.asitplus.dif.ConstraintField
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.data.CredentialPresentationRequest

sealed interface CredentialMatchingResult<Credential: Any> {
    val presentationRequest: CredentialPresentationRequest
}

data class PresentationExchangeMatchingResult<Credential: Any>(
    override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    val matchingInputDescriptorCredentials: Map<String, Map<Credential, Map<ConstraintField, NodeList>>>,
) : CredentialMatchingResult<Credential>

data class DCQLMatchingResult<Credential: Any>(
    override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
    val dcqlQueryResult: DCQLQueryResult<Credential>,
) : CredentialMatchingResult<Credential>