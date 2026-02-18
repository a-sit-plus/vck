package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.agent.HolderDCQLQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationExchangeQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationRequestMatchingResult
import at.asitplus.wallet.lib.data.CredentialPresentationRequest

/**
 * This interface represents the result of matching a [CredentialPresentationRequest]
 * against a list of available credentials
 */
sealed interface CredentialMatchingResult<Credential: Any> {
    val presentationRequest: CredentialPresentationRequest
    val matchingResult: HolderPresentationRequestMatchingResult<Credential>
}

data class PresentationExchangeMatchingResult<Credential: Any>(
    override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    override val matchingResult: HolderPresentationExchangeQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential>

data class DCQLMatchingResult<Credential: Any>(
    override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
    override val matchingResult: HolderDCQLQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential>