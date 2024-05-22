package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.wallet.lib.oidc.OpenIdConstants
import kotlinx.serialization.Serializable

@Serializable
sealed interface ResponseModeParameters {
    val responseMode: OpenIdConstants.ResponseMode

    @Serializable
    data class DirectPost(val responseUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode.DIRECT_POST
            get() = OpenIdConstants.ResponseMode.DIRECT_POST
    }

    @Serializable
    data class DirectPostJwt(val responseUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode.DIRECT_POST_JWT
            get() = OpenIdConstants.ResponseMode.DIRECT_POST_JWT
    }

    @Serializable
    data class Query(val redirectUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode.QUERY
            get() = OpenIdConstants.ResponseMode.QUERY
    }

    @Serializable
    data class Fragment(val redirectUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode.FRAGMENT
            get() = OpenIdConstants.ResponseMode.FRAGMENT
    }
}