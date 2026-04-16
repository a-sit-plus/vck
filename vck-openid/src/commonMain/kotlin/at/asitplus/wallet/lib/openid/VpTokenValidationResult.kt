package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult

sealed interface VpTokenValidationResult {
    val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
}

data class VpTokenValidationResultDCQL(
    val credentialQueryResponseValidations: Map<DCQLCredentialQueryIdentifier, List<KmmResult<VerifyPresentationResult>>>,
    val submissionRequirementsValidationResult: KmmResult<Unit>,
) : VpTokenValidationResult {
    @Deprecated("Replaced in favour of more descriptive name", ReplaceWith("credentialQueryResponseValidations"))
    @Suppress("unused")
    val allValidationResults
        get() = credentialQueryResponseValidations

    override val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
        get() = credentialQueryResponseValidations.flatMap {
            it.value
        }
}

data class VpTokenValidationResultPresentationExchange(
    val inputDescriptorResponseValidations: Map<String, KmmResult<VerifyPresentationResult>>,
) : VpTokenValidationResult {
    override val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
        get() = inputDescriptorResponseValidations.map {
            it.value
        }
}