package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlinx.datetime.Instant

data class VcJwsTimelinessValidationDetails(
    val evaluationTime: Instant,
    val jwsExpiredError: EntityExpiredError?,
    val credentialExpiredError: EntityExpiredError?,
    val jwsNotYetValidError: EntityNotYetValidError?,
    val credentialNotYetValidError: EntityNotYetValidError?,
) {
    val isSuccess = listOf(
        jwsExpiredError,
        credentialExpiredError,
        jwsNotYetValidError,
        credentialNotYetValidError,
    ).all { it == null }
}

