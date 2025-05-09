package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

data class VcJwsVerificationResultWrapper(
    val vcJws: VerifiableCredentialJws,
    val tokenStatus: KmmResult<TokenStatus>?,
    val timelinessValidationSummary: CredentialTimelinessValidationSummary.VcJws,
)