package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.wallet.lib.data.dif.PresentationPreparationState
import at.asitplus.wallet.lib.oidc.AuthenticationRequest
import at.asitplus.wallet.lib.oidc.RelyingPartyMetadata
import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationResponsePreparationState(
    val request: AuthenticationRequest,
    val nonce: String,
    val responseType: String,
    val clientMetadata: RelyingPartyMetadata,
    val clientJsonWebKeySet: JsonWebKeySet?,
    val audience: String,
    val responseModeParameters: ResponseModeParameters,
    val clientIdSchemeParameters: ClientIdSchemeParameters?,
    val presentationPreparationState: PresentationPreparationState?,
)
