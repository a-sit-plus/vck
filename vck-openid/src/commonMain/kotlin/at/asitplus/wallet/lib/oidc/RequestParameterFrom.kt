package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersSerializer
import kotlinx.serialization.Serializable

@Serializable
sealed interface RequestParametersFrom {
    @Serializable(with  = RequestParametersSerializer::class)
    val parameters: RequestParameters
}