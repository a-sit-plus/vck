package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlinx.datetime.Instant

data class SdJwtTimelinessValidationSummary(
    val evaluationTime: Instant,
    val jwsExpiredError: EntityExpiredError?,
    val jwsNotYetValidError: EntityNotYetValidError?,
) {
    val isSuccess = listOf(
        jwsExpiredError,
        jwsNotYetValidError,
    ).all { it == null }
}