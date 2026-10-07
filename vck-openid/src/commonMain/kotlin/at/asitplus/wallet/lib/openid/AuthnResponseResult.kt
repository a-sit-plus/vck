package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * An authorization response of the wallet, processed by [OpenId4VpVerifier.validateAuthnResponse] or
 * [DcApiVerifier.validateAuthnResponse]: correlated with its [request], which processing it has consumed, so that
 * the request can't be answered again.
 *
 * A processed response is either a presentation, see [Success], or an authorization error response, see [Error].
 * Answer both with [directPostHttpResponse] for the response modes `direct_post` and `direct_post.jwt`
 * (OpenID4VP 1.0, 8.2). A response that has not been processed, i.e. that is malformed, can't be correlated with a
 * request, or violates the protection its request requires, fails `validateAuthnResponse` instead.
 */
sealed interface AuthnResponseResult : DcApiResponseResult {

    /** The request this response answers, consumed by processing the response. */
    val request: AuthenticationRequestParameters

    /** The `state` of [request], to find the transaction of the integrator. */
    val state: String?
        get() = request.state

    /** The wallet presented: [vpTokenResult] tells whether the presentation is valid. */
    data class Success(
        val vpTokenResult: KmmResult<VpTokenValidationResult>,
        override val request: AuthenticationRequestParameters,
    ) : AuthnResponseResult

    /**
     * The wallet answered with an authorization error response (OpenID4VP 1.0, 8.2, 8.5, A.4), e.g. because the user
     * declined. The error ends the request like a presentation, so another attempt needs a new request.
     *
     * [OAuth2Error.errorDescription] and [OAuth2Error.errorUri] are controlled by the wallet, so escape them when
     * displaying them. Over the Digital Credentials API, only [OAuth2Error.error] is set.
     */
    data class Error(
        val error: OAuth2Error,
        override val request: AuthenticationRequestParameters,
    ) : AuthnResponseResult
}
