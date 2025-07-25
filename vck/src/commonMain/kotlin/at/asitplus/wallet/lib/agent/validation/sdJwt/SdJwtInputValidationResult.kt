package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.SdJwtDecoded
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.jws.SdJwtSigned

data class SdJwtInputValidationResult(
    val input: SdJwtSigned,
    val isIntegrityGood: Boolean,
    val payloadCredentialValidationSummary: KmmResult<SdJwtCredentialPayloadValidationSummary>,
    val payloadJsonValidationSummary: KmmResult<SdJwtDecoded>,
    val payload: KmmResult<Verifier.VerifyCredentialResult.SuccessSdJwt>,
) {
    val isSuccess: Boolean
        get() = listOf(
            isIntegrityGood,
            payloadCredentialValidationSummary.isSuccess,
            payloadJsonValidationSummary.isSuccess,
            payload.isSuccess
        ).all { it }
}