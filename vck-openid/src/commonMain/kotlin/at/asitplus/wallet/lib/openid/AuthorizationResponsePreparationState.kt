package at.asitplus.wallet.lib.openid

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlinx.serialization.Serializable

@Serializable
data class AuthorizationResponsePreparationState(
    val credentialPresentationRequest: CredentialPresentationRequest?,
    val clientMetadata: RelyingPartyMetadata?,
) {
    @Deprecated("Access through credentialPresentationRequest instead.")
    val presentationDefinition: PresentationDefinition?
        get() = if (credentialPresentationRequest is CredentialPresentationRequest.PresentationExchangeRequest) {
            credentialPresentationRequest.presentationDefinition
        } else {
            null
        }

    @Deprecated("Use default constructor")
    constructor(
        presentationDefinition: PresentationDefinition?,
        clientMetadata: RelyingPartyMetadata?,
    ) : this(
        clientMetadata = clientMetadata,
        credentialPresentationRequest = presentationDefinition?.let {
            CredentialPresentationRequest.PresentationExchangeRequest(
                presentationDefinition,
                null
            )
        }
    )
}