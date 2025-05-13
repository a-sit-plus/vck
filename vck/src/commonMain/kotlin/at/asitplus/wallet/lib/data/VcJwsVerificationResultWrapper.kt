package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult

data class VcJwsVerificationResultWrapper(
    val vcJws: VerifiableCredentialJws,
    val tokenStatus: TokenStatusValidationResult,
    val timelinessValidationSummary: CredentialTimelinessValidationSummary.VcJws,
)