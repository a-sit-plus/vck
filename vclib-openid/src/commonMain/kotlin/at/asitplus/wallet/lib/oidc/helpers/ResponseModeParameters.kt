package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.wallet.lib.oidc.OpenIdConstants
import kotlinx.serialization.Serializable

@Serializable
sealed interface ResponseModeParameters {
    val responseMode: OpenIdConstants.ResponseMode

    @Serializable
    class DirectPost(val responseUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode
            get() = OpenIdConstants.ResponseMode.DIRECT_POST
    }

    @Serializable
    class DirectPostJwt(val responseUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode
            get() = OpenIdConstants.ResponseMode.DIRECT_POST_JWT
    }

    @Serializable
    class Query(val redirectUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode
            get() = OpenIdConstants.ResponseMode.QUERY
    }

    @Serializable
    class Fragment(val redirectUrl: String) : ResponseModeParameters {
        override val responseMode: OpenIdConstants.ResponseMode
            get() = OpenIdConstants.ResponseMode.FRAGMENT
    }
}