package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult

data class VcJwsVerificationResultWrapper(
    val vcJws: VerifiableCredentialJws,
    val freshnessSummary: CredentialFreshnessSummary.VcJws,
) {
    @Suppress("unused")
    @Deprecated("Replaced with more expressive TokenStatusValidationResult, supporting token status values as defined by the library client.", ReplaceWith("freshnessSummary.tokenStatusValidationResult"))
    val tokenStatus: KmmResult<TokenStatus>?
        get() = when(val it = freshnessSummary.tokenStatusValidationResult) {
            is TokenStatusValidationResult.Invalid -> KmmResult.success(it.tokenStatus)
            is TokenStatusValidationResult.Rejected -> KmmResult.failure(it.throwable)
            is TokenStatusValidationResult.Valid -> it.tokenStatus?.let { KmmResult.success(it) }
        }

    @Suppress("unused")
    @Deprecated("Moved to content of other member.", ReplaceWith("freshnessSummary.timelinessValidationSummary"))
    val timelinessValidationSummary: CredentialTimelinessValidationSummary.VcJws
        get() = freshnessSummary.timelinessValidationSummary
}