package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.oidc.RelyingPartyMetadata
import kotlinx.serialization.Serializable

@Serializable
data class AuthorizationResponsePreparationState(
    val presentationDefinition: PresentationDefinition?,
    val clientMetadata: RelyingPartyMetadata?,
)
