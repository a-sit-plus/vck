package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.validation.PresentationValidationResult

sealed interface VpTokenValidationResult

/**
 * The legacy result of a `vp_token`, projected from [presentationValidations] under the presentation policy of the
 * verifier: an accepted presentation becomes its [VerifyPresentationResult], a rejected one fails with the cause of
 * its first rejecting check.
 */
data class VpTokenValidationResultDCQL(
    /**
     * The presentations by the credential query they answer, validated with a
     * [at.asitplus.wallet.lib.validation.CredentialValidator]: an mdoc `DeviceResponse` yields one per document.
     * Their reports are the children of [AuthnResponseResult.Success.validationReport].
     */
    val presentationValidations: Map<DCQLCredentialQueryIdentifier, List<PresentationValidationResult>> = emptyMap(),
) : VpTokenValidationResult {

}

