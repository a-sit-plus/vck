package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.wallet.lib.oidc.OpenIdConstants
import kotlinx.serialization.Serializable

@Serializable
sealed class ResponseModeParameters(val responseMode: OpenIdConstants.ResponseMode) {
    @Serializable
    data class DirectPost(val responseUrl: String) :
        ResponseModeParameters(OpenIdConstants.ResponseMode.DIRECT_POST)

    @Serializable
    data class DirectPostJwt(val responseUrl: String) :
        ResponseModeParameters(OpenIdConstants.ResponseMode.DIRECT_POST_JWT)

    @Serializable
    data class Query(val redirectUrl: String) :
        ResponseModeParameters(OpenIdConstants.ResponseMode.QUERY)

    @Serializable
    data class Fragment(val redirectUrl: String) :
        ResponseModeParameters(OpenIdConstants.ResponseMode.FRAGMENT)
}