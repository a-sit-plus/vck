package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.wallet.lib.data.dif.PresentationPreparationState
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.RelyingPartyMetadata
import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationResponsePreparationState(
    val parameters: AuthenticationRequestParameters,
    val nonce: String,
    val responseType: String,
    val clientMetadata: RelyingPartyMetadata,
    val audience: String,
    val responseModeParameters: ResponseModeParameters,
    val clientIdSchemeParameters: ClientIdSchemeParameters?,
    val presentationPreparationState: PresentationPreparationState?,
)
