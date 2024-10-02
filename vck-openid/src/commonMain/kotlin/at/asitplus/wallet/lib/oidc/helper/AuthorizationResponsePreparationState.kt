package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.RelyingPartyMetadata
import kotlinx.serialization.Serializable

@Serializable
data class AuthorizationResponsePreparationState(
    val presentationDefinition: PresentationDefinition?,
    val clientMetadata: RelyingPartyMetadata?,
)
