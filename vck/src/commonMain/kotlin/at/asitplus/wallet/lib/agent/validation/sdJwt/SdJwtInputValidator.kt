package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.SdJwtValidator
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class SdJwtInputValidator(
    private val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) {
    suspend operator fun invoke(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): SdJwtInputValidationResult {
        val payloadCredentialValidationSummary = sdJwtSigned.getPayloadAsVerifiableCredentialSdJwt().map { sdJwt ->
            SdJwtCredentialPayloadValidationSummary(verifiableCredentialSdJwt = sdJwt)
        }.onFailure { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
        }

        val payloadJsonValidationSummary = sdJwtSigned.getPayloadAsJsonObject().map { jsonObject ->
            SdJwtValidator(sdJwtSigned)
        }.onFailure { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
        }

        val credentialPayload = payloadCredentialValidationSummary.getOrNull()
        val sdJwtValidator = payloadJsonValidationSummary.getOrNull()

        val payloadValidationSummary = if (credentialPayload == null) {
            KmmResult.failure(payloadCredentialValidationSummary.exceptionOrNull()!!)
        } else if (sdJwtValidator == null) {
            KmmResult.failure(payloadJsonValidationSummary.exceptionOrNull()!!)
        } else {
            val reconstructedJsonObject = sdJwtValidator.reconstructedJsonObject ?: buildJsonObject { }

            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            val validDisclosures: Map<String, SelectiveDisclosureItem> = sdJwtValidator.validDisclosures

            KmmResult.success(
                Verifier.VerifyCredentialResult.SuccessSdJwt(
                    sdJwtSigned = sdJwtSigned,
                    verifiableCredentialSdJwt = credentialPayload.verifiableCredentialSdJwt,
                    reconstructedJsonObject = reconstructedJsonObject,
                    disclosures = validDisclosures,
                )
            )
        }

        return SdJwtInputValidationResult(
            input = sdJwtSigned,
            isIntegrityGood = verifyJwsObject(sdJwtSigned.jws).also {
                if (!it) {
                    Napier.w("verifySdJwt: Signature invalid")
                }
            },
            payloadCredentialValidationSummary = payloadCredentialValidationSummary,
            payloadJsonValidationSummary = payloadJsonValidationSummary,
            payload = payloadValidationSummary,
        )
    }
}

