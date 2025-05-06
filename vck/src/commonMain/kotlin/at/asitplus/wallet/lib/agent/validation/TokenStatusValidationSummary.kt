package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

data class TokenStatusValidationSummary(
    val status: Status,
    /**
     * Provides an exception in case validation failed.
     */
    val tokenStatus: KmmResult<TokenStatus>
)