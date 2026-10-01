package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.CredentialPresentationRequest

/**
 * Result of matching a [CredentialPresentationRequest] against the holder's available credentials.
 *
 * The paired [presentationRequest] and [matchingResult] preserve the request language's selection rules. Applications
 * inspect the corresponding subtype, obtain user consent, and turn the chosen matches into a credential presentation;
 * this object itself is neither a submission nor a protocol response.
 */
sealed interface CredentialMatchingResult<Credential : Any> {
    val presentationRequest: CredentialPresentationRequest
    val matchingResult: HolderPresentationRequestMatchingResult<Credential>
}

@Suppress("DEPRECATION")
@Deprecated("Support for Presentation Exchange been removed from OpenID4VP")
data class PresentationExchangeMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    override val matchingResult: HolderPresentationExchangeQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential>

data class DCQLMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
    override val matchingResult: HolderDCQLQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential>

data class IsoDeviceRetrievalMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.IsoDeviceRetrieval,
    override val matchingResult: HolderIsoDeviceRetrievalQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential>
