package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class SdJwtTimelinessValidationSummary(
    val evaluationTime: Instant,
    val jwsExpiredError: JwsExpiredError?,
    val jwsNotYetValidError: JwsNotYetValidError?,
) {
    val isSuccess = listOf(
        jwsExpiredError,
        jwsNotYetValidError,
    ).all { it == null }
}