package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.validation.PresentationValidationResult

sealed interface VpTokenValidationResult {
    @Deprecated(
        "Projected from AuthnResponseResult.Success.presentationValidations, use them and validationReport. " +
                "To be removed in the next major release."
    )
    val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
}

/**
 * The legacy result of a `vp_token`, projected from [presentationValidations] under the presentation policy of the
 * verifier: an accepted presentation becomes its [VerifyPresentationResult], a rejected one fails with the cause of
 * its first rejecting check.
 */
data class VpTokenValidationResultDCQL(
    @Deprecated(
        "Projected from presentationValidations, use AuthnResponseResult.Success.presentationValidations and " +
                "validationReport. To be removed in the next major release."
    )
    val credentialQueryResponseValidations: Map<DCQLCredentialQueryIdentifier, List<KmmResult<VerifyPresentationResult>>>,
    @Deprecated(
        "The submissionRequirements check of AuthnResponseResult.Success.validationReport. " +
                "To be removed in the next major release."
    )
    val submissionRequirementsValidationResult: KmmResult<Unit>,
    /**
     * The presentations by the credential query they answer, validated with a
     * [at.asitplus.wallet.lib.validation.CredentialValidator]: an mdoc `DeviceResponse` yields one per document.
     * Their reports are the children of [AuthnResponseResult.Success.validationReport].
     */
    val presentationValidations: Map<DCQLCredentialQueryIdentifier, List<PresentationValidationResult>> = emptyMap(),
) : VpTokenValidationResult {

    @Deprecated(
        "Projected from AuthnResponseResult.Success.presentationValidations, use them and validationReport. " +
                "To be removed in the next major release."
    )
    @Suppress("DEPRECATION")
    override val presentationResults: Collection<KmmResult<VerifyPresentationResult>>
        get() = credentialQueryResponseValidations.flatMap {
            it.value
        }
}

