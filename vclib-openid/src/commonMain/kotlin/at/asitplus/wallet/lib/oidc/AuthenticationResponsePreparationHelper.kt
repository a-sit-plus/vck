package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.PresentationPreparationHelper
import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationResponsePreparationHelper(
    val parameters: AuthenticationRequestParameters,
    val nonce: String,
    val responseType: String,
    val clientMetadata: RelyingPartyMetadata,
    val audience: String,
    val responseModeParameters: ResponseModeParameters,
    val clientIdSchemeParameters: ClientIdSchemeParameters?,
    val presentationPreparationHelper: PresentationPreparationHelper?,
)
