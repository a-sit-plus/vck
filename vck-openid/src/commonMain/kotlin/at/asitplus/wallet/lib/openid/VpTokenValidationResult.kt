package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult

sealed interface VpTokenValidationResult

data class VpTokenValidationResultDCQL(
    val allValidationResults: Map<DCQLCredentialQueryIdentifier, List<KmmResult<VerifyPresentationResult>>>,
) : VpTokenValidationResult

data class VpTokenValidationResultPresentationExchange(
    val inputDescriptorResponseValidations: Map<String, KmmResult<VerifyPresentationResult>>,
) : VpTokenValidationResult