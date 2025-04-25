package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

data class TokenStatusValidationSummary(
    val status: Status,
    /**
     * Provides an exception in case validation failed.
     */
    val tokenStatus: KmmResult<TokenStatus>
) {
    val isValidationRejected = tokenStatus.isFailure
    val isConfirmedInvalid = tokenStatus.getOrNull() == TokenStatus.Invalid
    val isConfirmedNotInvalid = tokenStatus.getOrNull() == TokenStatus.Invalid
}