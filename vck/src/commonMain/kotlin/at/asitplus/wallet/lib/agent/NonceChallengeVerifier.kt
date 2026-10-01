package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.cosef.CoseSigned
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
 * the challenge it answers: the [ChallengeSession] passes the challenge to the SD-JWT and VC-JWT verification of
 * the delegate, and hands it to the caller-provided factory that builds the mdoc device signature check, which
 * binds it through the session transcript. [verifier] is the plain [Verifier] to use where a challenge is out of
 * scope, e.g. ISO/IEC 18013-7 Annex C responses, and [nonceService] is the raw nonce store.
 *
 * The deprecated `verifyPresentation*` methods here instead take the challenge from the presentation itself and
 * accept it as long as it is still known to [nonceService], i.e. a presentation created for one request also
 * satisfies another request of ours that is still open.
 */
class NonceChallengeVerifier @JvmOverloads constructor(
    val verifierId: String,
    val verifier: Verifier = VerifierAgent(identifier = verifierId),
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
        returnOneDeviceResponse = returnOneDeviceResponse,
    )

    @Deprecated("Use createPresentationRequest(transactionData, returnOneDeviceResponse, calcIsoSessionTranscript) instead")
    suspend fun createPresentationRequest(
        transactionData: List<TransactionDataBase64Url>? = null,
        calcIsoDeviceSignaturePlain: suspend (IsoDeviceSignatureInput) -> CoseSigned<ByteArray>?,
        returnOneDeviceResponse: Boolean = false,
    ) = PresentationRequestParameters(
        nonce = nonceService.provideNonce(),
        audience = verifierId,
        transactionData = transactionData,
        calcIsoDeviceSignaturePlain = calcIsoDeviceSignaturePlain,
        returnOneDeviceResponse = returnOneDeviceResponse,
    )

    /**
     * Uses the challenge embedded in the SD-JWT key binding JWT.
     *
     * @param audience Exact audience expected in the key binding JWT. When `null`, the wrapped [Verifier] applies its
     * default. Protocol callers must pass their transport-specific audience, such as `origin:<origin>` for
     * OpenID4VP over the DC API.
     */
    @Deprecated(
        "Consume the challenge of the request that was answered with consumeChallenge(), " +
                "and verify the presentations of that response with the returned ChallengeSession"
    )
    suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        transactionData: List<TransactionDataBase64Url>? = null,
        requireCryptographicHolderBinding: Boolean = true,
        audience: String? = null,
    ): KmmResult<VerifyPresentationResult.SuccessSdJwt> = verifyWithChallenge(
        challenge = input.keyBindingJws?.payload?.challenge,
        missingChallengeMessage = "No key binding JWT",
    ) { challenge ->
        verifier.verifyPresentationSdJwt(
            input = input,
            challenge = challenge,
            transactionData = transactionData,
            requireCryptographicHolderBinding = requireCryptographicHolderBinding,
            audience = audience,
        )
    }

    /** Uses the challenge embedded in the VP JWT. */
    @Deprecated(
        "Consume the challenge of the request that was answered with consumeChallenge(), " +
                "and verify the presentations of that response with the returned ChallengeSession"
    )
    suspend fun verifyPresentationVcJwt(
        input: JwsCompactTyped<VerifiablePresentationJws>,
    ): KmmResult<VerifyPresentationResult.Success> = verifyWithChallenge(
        challenge = input.payload.challenge,
        missingChallengeMessage = "nonce missing",
    ) { challenge ->
        verifier.verifyPresentationVcJwt(
            input = input,
            challenge = challenge,
        )
    }

    @Deprecated(
        "Consume the challenge of the request that was answered with consumeChallenge(), " +
                "and verify the presentations of that response with the returned ChallengeSession"
    )
    suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
        challenge: String,
    ): KmmResult<VerifyPresentationResult.SuccessIso> = verifyWithChallenge(
        challenge = challenge,
        missingChallengeMessage = "nonce missing",
    ) {
        verifier.verifyPresentationIsoMdoc(input, verifyDocument)
    }

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

        /** @see Verifier.verifyPresentationSdJwt */
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
        suspend fun verifyPresentationVcJwt(
            input: JwsCompactTyped<VerifiablePresentationJws>,
        ): KmmResult<VerifyPresentationResult.Success> = verifier.verifyPresentationVcJwt(
            input = input,
            challenge = challenge,
        )

        /** @see Verifier.verifyUnsignedVcJws */
        suspend fun verifyUnsignedVcJws(
            input: String,
        ): KmmResult<VerifyPresentationResult.SuccessUnsigned> = verifier.verifyUnsignedVcJws(input)

        /**
         * @param verifyDocument Builds the check for the mdoc device signature from the [challenge] that the
         * presentations of this response answer, e.g. from the session transcript binding it, see
         * [at.asitplus.wallet.lib.MdocDeviceSignatureVerifier].
         * @see Verifier.verifyPresentationIsoMdoc
         */
        suspend fun verifyPresentationIsoMdoc(
            input: DeviceResponse,
            verifyDocument: (challenge: String) -> suspend (MobileSecurityObject, Document) -> Boolean,
        ): KmmResult<VerifyPresentationResult.SuccessIso> =
            verifier.verifyPresentationIsoMdoc(input, verifyDocument(challenge))
    }

    /** Consume only after delegated verification succeeds, so failed attempts do not burn a valid challenge. */
    private suspend fun <T> verifyWithChallenge(
        challenge: String?,
        missingChallengeMessage: String,
        verify: suspend (String) -> KmmResult<T>,
    ): KmmResult<T> = catching {
        val nonce = challenge ?: throw IllegalArgumentException(missingChallengeMessage)
        require(nonceService.verifyNonce(nonce)) { "nonce invalid: $nonce" }
        val result = verify(nonce).getOrThrow()
        consumeChallenge(nonce)
        result
    }
}
