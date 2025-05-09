package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt

data class SdJwtCredentialPayloadValidationSummary(
    val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
    val subjectMatchingResult: SubjectMatchingResult?,
) {
    val isSuccess: Boolean
        get() = subjectMatchingResult?.isSuccess != false
}