package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.PresentationPreparationState
import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationResponsePreparationState(
    val parameters: AuthenticationRequestParameters,
    val responseType: String,
    val targetUrl: String,
    val clientMetadata: RelyingPartyMetadata,
    val audience: String,
    val nonce: String,
    val presentationPreparationState: PresentationPreparationState?,
)
