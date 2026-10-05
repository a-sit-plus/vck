package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.rfc6749OAuth2AuthorizationFramework.ResponseType
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier.ChallengeSession
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * The lifecycle of an authorization response, shared by [OpenId4VpVerifier] and [DcApiVerifier], which continue with
 * the checks of their transport and the validation of the `vp_token` on the [ConsumedResponse].
 *
 * A response that can be correlated with its request ends that request, no matter how validating it turns out, as
 * authorization responses are not retryable: the request is removed from the store, its nonce consumed, and its
 * ephemeral encryption key removed, before anything else can fail.
 */
internal class AuthnResponseProcessor(
    private val requestFactory: OpenId4VpRequestFactory,
    private val nonceAwareVerifier: NonceChallengeVerifier,
) {

    /**
     * A response correlated with its [request], which has been consumed along with its nonce and ephemeral
     * encryption key. The response is the wallet's authorization [error], or else a presentation, to verify with
     * [session].
     */
    data class ConsumedResponse(
        val request: AuthenticationRequestParameters,
        val session: ChallengeSession,
        val error: OAuth2Error?,
    )

    /**
     * Correlates [input] by [externalId] (DC API) or else by its `state` (URL/QR), and ends the lifecycle of that
     * request. Then validates what does not depend on the transport: the content of [input], see [authorizationError], its
     * protection as the request requires it, and the response type of the request.
     *
     * The ephemeral encryption key is no longer needed after this: decrypting the response happens while parsing it,
     * and validating the `vp_token` only needs the public key from the request.
     *
     * @throws IllegalArgumentException if [input] can not be correlated, or violates the request
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun consume(
        input: ResponseParametersFrom,
        externalId: String?,
    ): ConsumedResponse {
        val request = requestFactory.consumeAuthnRequest(input, externalId)
        try {
            // end the challenge's lifecycle before anything else can fail
            val session = nonceAwareVerifier.consumeChallenge(
                requireNotNull(request.nonce) { "nonce not present in $request" }
            )
            val error = input.authorizationError()
            requestFactory.validateResponseProtection(request, input, error)
            request.requireVpTokenResponseType()
            return ConsumedResponse(request, session, error)
        } finally {
            withContext(NonCancellable) { requestFactory.discardEphemeralResponseKey(request) }
        }
    }

    private fun AuthenticationRequestParameters.requireVpTokenResponseType() {
        val responseType = requireNotNull(responseType?.let { ResponseType(it) }) {
            "No response type was specified in the original authentication request."
        }
        require(OpenIdConstants.VP_TOKEN in responseType) {
            "Response type must contain `vp_token`"
        }
    }
}
