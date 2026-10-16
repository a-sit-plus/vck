package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.validation.PresentationValidationResult

sealed interface VpTokenValidationResult {
    val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
}

// TODO Rename to DCQL only?
data class VpTokenValidationResultDCQL(
    val credentialQueryResponseValidations: Map<DCQLCredentialQueryIdentifier, List<KmmResult<VerifyPresentationResult>>>,
    val submissionRequirementsValidationResult: KmmResult<Unit>,
    /**
     * The presentations by the credential query they answer, validated with a
     * [at.asitplus.wallet.lib.validation.CredentialValidator]: an mdoc `DeviceResponse` yields one per document.
     * Their reports are the children of [AuthnResponseResult.Success.validationReport].
     */
    val presentationValidations: Map<DCQLCredentialQueryIdentifier, List<PresentationValidationResult>> = emptyMap(),
) : VpTokenValidationResult {

    override val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
        get() = credentialQueryResponseValidations.flatMap {
            it.value
        }
}

