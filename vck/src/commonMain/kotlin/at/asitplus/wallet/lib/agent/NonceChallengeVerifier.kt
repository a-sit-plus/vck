package at.asitplus.wallet.lib.agent

import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.validation.PresentationContext
import kotlin.jvm.JvmOverloads

/**
 * Owns the lifecycle of the challenges that presentations are verified against: mint one with
 * [createPresentationRequest], spend it with [consumeChallenge] once the response to that request arrives, and
 * verify the presentations of that response with the [ChallengeSession] it returns.
 *
 * [ChallengeSession.context] carries the challenge into the validation of every
 * presentation with [at.asitplus.wallet.lib.validation.CredentialValidator]. [nonceService] is the raw nonce store.
 */
class NonceChallengeVerifier @JvmOverloads constructor(
    val verifierId: String,
    val nonceService: NonceService = DefaultNonceService(),
) {

    /**
     * Holder-facing presentation request input using a fresh challenge.
     *
     * @param returnOneDeviceResponse compatibility switch for deprecated Presentation Exchange only. Direct ISO
     * Device Retrieval always returns one DeviceResponse.
     */
    suspend fun createPresentationRequest(
        transactionData: List<TransactionDataBase64Url>? = null,
        calcIsoSessionTranscript: suspend () -> SessionTranscript? = { null },
        returnOneDeviceResponse: Boolean = false,
    ) = PresentationRequestParameters(
        nonce = nonceService.provideNonce(),
        audience = verifierId,
        transactionData = transactionData,
        calcIsoSessionTranscript = calcIsoSessionTranscript,
    )

    /**
     * Consumes the challenge that has been answered: it must be one of ours, and it must not be usable again.
     *
     * Protocol verifiers call this as soon as they have loaded the request a response refers to, since an
     * authentication response is not retryable, and verify the presentations of that response with the returned
     * [ChallengeSession], no matter how that validation turns out.
     */
    suspend fun consumeChallenge(challenge: String): ChallengeSession {
        require(nonceService.verifyAndRemoveNonce(challenge)) { "nonce invalid or already used: $challenge" }
        return ChallengeSession(challenge)
    }

    /**
     * A challenge of ours that has been answered and is consumed, i.e. no longer known to
     * [at.asitplus.wallet.lib.NonceService], to verify the presentations of that one response with.
     *
     * A response may contain several presentations, but they all answer the single [challenge] of the request,
     * so it is verified and consumed once, in [consumeChallenge], and not per presentation.
     */
    inner class ChallengeSession internal constructor(internal val challenge: String) {

        /**
         * The context of a presentation answering this challenge, for
         * [at.asitplus.wallet.lib.validation.CredentialValidator.validate]: the challenge always is the consumed one.
         *
         * @param audience the client identifier, or `origin:<origin>` over the Digital Credentials API
         * @param sessionTranscript the transport-specific session transcript, required for mdoc device authentication
         * @param requireHolderBinding DCQL `require_cryptographic_holder_binding` of the credential query
         */
        @JvmOverloads
        fun context(
            audience: String,
            sessionTranscript: SessionTranscript? = null,
            transactionData: List<TransactionDataBase64Url>? = null,
            requireHolderBinding: Boolean = true,
        ) = PresentationContext(
            challenge = challenge,
            audience = audience,
            sessionTranscript = sessionTranscript,
            transactionData = transactionData,
            requireHolderBinding = requireHolderBinding,
        )

    }

}
