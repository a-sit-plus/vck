package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlinx.serialization.Serializable

@Serializable
data class AuthorizationResponsePreparationState(
    val credentialPresentationRequest: CredentialPresentationRequest?,
    val clientMetadata: RelyingPartyMetadata?,
)