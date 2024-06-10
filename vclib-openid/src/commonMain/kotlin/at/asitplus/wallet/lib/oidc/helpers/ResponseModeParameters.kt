package at.asitplus.wallet.lib.oidc.helpers

import kotlinx.serialization.Serializable

@Serializable
sealed class ResponseModeParameters {
    @Serializable
    data class DirectPost(val responseUrl: String) : ResponseModeParameters()

    @Serializable
    data class DirectPostJwt(
        val responseUrl: String,
    ) : ResponseModeParameters()

    @Serializable
    data class Query(val redirectUrl: String) : ResponseModeParameters()

    @Serializable
    data class Fragment(val redirectUrl: String) : ResponseModeParameters()
}