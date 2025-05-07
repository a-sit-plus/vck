package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlinx.datetime.Instant

data class MobileSecurityObjectTimelinessValidationSummary(
    val evaluationTime: Instant,
    val mdocExpiredError: EntityExpiredError?,
    val mdocNotYetValidError: EntityNotYetValidError?,
) {
    val isSuccess = listOf(
        mdocExpiredError,
        mdocNotYetValidError,
    ).all { it == null }
}