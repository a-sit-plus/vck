package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt

data class SdJwtCredentialPayloadValidationSummary(
    val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
) {
    val isSuccess: Boolean
        get() = true
}