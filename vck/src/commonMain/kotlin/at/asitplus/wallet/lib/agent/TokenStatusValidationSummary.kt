package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus


sealed interface TokenStatusValidationSummary {
    val status: Status

    data class Rejected(
        override val status: Status,
        val throwable: Throwable,
    ) : TokenStatusValidationSummary

    data class Success(
        override val status: Status,
        val tokenStatus: TokenStatus,
    ) : TokenStatusValidationSummary
}