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
 * Adds nonce-backed challenge creation and replay protection to a plain [Verifier].
 *
 * [VerifierAgent] remains the explicit-challenge verifier; this wrapper owns the challenge lifecycle.
 */
class NonceChallengeVerifier @JvmOverloads constructor(
    val verifierId: String,
    val verifier: Verifier = VerifierAgent(identifier = verifierId),
    val nonceService: NonceService = DefaultNonceService(),
) : Verifier by verifier,
    NonceService by nonceService {

    /**
     * Holder-facing presentation request input using a fresh challenge.
     *
     * @param returnOneDeviceResponse compatibility switch for deprecated Presentation Exchange only. Direct ISO
     * Device Retrieval always returns one DeviceResponse.
     */
    suspend fun createPresentationRequest(
        transactionData: List<TransactionDataBase64Url>? = null,
        calcIsoDeviceSignaturePlain: suspend (IsoDeviceSignatureInput) -> CoseSigned<ByteArray>? = { null },
        returnOneDeviceResponse: Boolean = false,
        calcIsoSessionTranscript: suspend () -> SessionTranscript = { throw IllegalStateException(
            "Session transcript calculation callback was not provided. This is required for ISO mDoc presentations.") },
    ) = PresentationRequestParameters(
        nonce = provideNonce(),
        audience = verifierId,
        transactionData = transactionData,
        calcIsoDeviceSignaturePlain = calcIsoDeviceSignaturePlain,
        calcIsoSessionTranscript = calcIsoSessionTranscript,
        returnOneDeviceResponse = returnOneDeviceResponse,
    )

    /**
     * Uses the challenge embedded in the SD-JWT key binding JWT.
     *
     * @param audience Exact audience expected in the key binding JWT. When `null`, the wrapped [Verifier] applies its
     * default. Protocol callers must pass their transport-specific audience, such as `origin:<origin>` for
     * OpenID4VP over the DC API.
     */
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

    /** Consume only after delegated verification succeeds, so failed attempts do not burn a valid challenge. */
    private suspend fun <T> verifyWithChallenge(
        challenge: String?,
        missingChallengeMessage: String,
        verify: suspend (String) -> KmmResult<T>,
    ): KmmResult<T> = catching {
        val nonce = challenge ?: throw IllegalArgumentException(missingChallengeMessage)
        require(verifyNonce(nonce)) { "nonce invalid: $nonce" }
        val result = verify(nonce).getOrThrow()
        require(verifyAndRemoveNonce(nonce)) { "nonce invalid or already used: $nonce" }
        result
    }
}
