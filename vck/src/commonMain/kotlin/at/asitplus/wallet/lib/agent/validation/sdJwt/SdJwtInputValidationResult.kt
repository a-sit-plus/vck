package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.SdJwtValidator
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.jws.SdJwtSigned

data class SdJwtInputValidationResult(
    val input: SdJwtSigned,
    val isIntegrityGood: Boolean,
    val payloadCredentialValidationSummary: KmmResult<SdJwtCredentialPayloadValidationSummary>,
    val payloadJsonValidationSummary: KmmResult<SdJwtValidator>,
    val payloadValidationSummary: KmmResult<Verifier.VerifyCredentialResult.SuccessSdJwt>,
) {
    val isSuccess: Boolean
        get() = listOf(
            isIntegrityGood,
            payloadCredentialValidationSummary.isSuccess,
            payloadJsonValidationSummary.isSuccess,
            payloadValidationSummary.isSuccess
        ).all { it }
}