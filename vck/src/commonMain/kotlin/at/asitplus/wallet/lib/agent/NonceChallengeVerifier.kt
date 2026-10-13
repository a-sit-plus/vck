package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.validation.PresentationContext
import at.asitplus.KmmResult
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlin.jvm.JvmOverloads

/**
 * Owns the lifecycle of the challenges that presentations are verified against: mint one with
 * [createPresentationRequest], spend it with [consumeChallenge] once the response to that request arrives, and
 * verify the presentations of that response with the [ChallengeSession] it returns.
 *
 * This is deliberately not a [Verifier] itself, so that a presentation cannot be verified without accounting for
 * the challenge it answers: [ChallengeSession.context] carries the challenge into the validation of every
 * presentation with [at.asitplus.wallet.lib.validation.CredentialValidator]. [nonceService] is the raw nonce store.
 */
class NonceChallengeVerifier @JvmOverloads constructor(
    val verifierId: String,
    val nonceService: NonceService = DefaultNonceService(),
) {

    /** Backs the deprecated presentation methods of [ChallengeSession]. */
    @Deprecated(
        "Validate presentations with CredentialValidator, in the context of ChallengeSession.context(). " +
                "To be removed in the next major release."
    )
    @Suppress("DEPRECATION")
    var verifier: Verifier = VerifierAgent(identifier = verifierId)
        private set

    @Deprecated(
        "Validate presentations with CredentialValidator, in the context of ChallengeSession.context(), " +
                "instead of verifier. To be removed in the next major release.",
        ReplaceWith("NonceChallengeVerifier(verifierId, nonceService)"),
    )
    @JvmOverloads
    constructor(
        verifierId: String,
        verifier: Verifier,
        nonceService: NonceService = DefaultNonceService(),
    ) : this(verifierId, nonceService) {
        @Suppress("DEPRECATION")
        this.verifier = verifier
    }

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

        /** @see Verifier.verifyPresentationSdJwt */
        @Deprecated(
            "Validate with CredentialValidator.validate(input, context(audience, ...), policy). " +
                    "To be removed in the next major release."
        )
        @Suppress("DEPRECATION")
        suspend fun verifyPresentationSdJwt(
            input: SdJwtSigned,
            transactionData: List<TransactionDataBase64Url>? = null,
            requireCryptographicHolderBinding: Boolean = true,
            audience: String? = null,
        ): KmmResult<VerifyPresentationResult.SuccessSdJwt> = verifier.verifyPresentationSdJwt(
            input = input,
            challenge = challenge,
            transactionData = transactionData,
            requireCryptographicHolderBinding = requireCryptographicHolderBinding,
            audience = audience,
        )

        /** @see Verifier.verifyPresentationVcJwt */
        @Deprecated(
            "Validate with CredentialValidator.validate(input, context(audience, ...), policy). " +
                    "To be removed in the next major release."
        )
        @Suppress("DEPRECATION")
        suspend fun verifyPresentationVcJwt(
            input: JwsCompactTyped<VerifiablePresentationJws>,
        ): KmmResult<VerifyPresentationResult.Success> = verifier.verifyPresentationVcJwt(
            input = input,
            challenge = challenge,
        )

        /** @see Verifier.verifyUnsignedVcJws */
        @Deprecated(
            "Validate with CredentialValidator.validate(input, context(audience, ...), policy). " +
                    "To be removed in the next major release."
        )
        @Suppress("DEPRECATION")
        suspend fun verifyUnsignedVcJws(
            input: String,
        ): KmmResult<VerifyPresentationResult.SuccessUnsigned> = verifier.verifyUnsignedVcJws(input)

        /**
         * @param verifyDocument Builds the check for the mdoc device signature from the [challenge] that the
         * presentations of this response answer, e.g. from the session transcript binding it, see
         * [at.asitplus.wallet.lib.MdocDeviceSignatureVerifier].
         * @see Verifier.verifyPresentationIsoMdoc
         */
        @Deprecated(
            "Validate with CredentialValidator.validate(input, context(audience, ...), policy). " +
                    "To be removed in the next major release."
        )
        @Suppress("DEPRECATION")
        suspend fun verifyPresentationIsoMdoc(
            input: DeviceResponse,
            verifyDocument: (challenge: String) -> suspend (MobileSecurityObject, Document) -> Boolean,
        ): KmmResult<VerifyPresentationResult.SuccessIso> =
            verifier.verifyPresentationIsoMdoc(input, verifyDocument(challenge))
    }

}
