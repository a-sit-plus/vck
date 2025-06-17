package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.agent.validation.TimelinessIndicator
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlinx.datetime.Instant

data class VcJwsTimelinessValidationDetails(
    override val evaluationTime: Instant,
    val jwsExpiredError: EntityExpiredError?,
    val credentialExpiredError: EntityExpiredError?,
    val jwsNotYetValidError: EntityNotYetValidError?,
    val credentialNotYetValidError: EntityNotYetValidError?,
): TimelinessIndicator {
    override val isExpired: Boolean
        get() = jwsExpiredError != null || credentialExpiredError != null

    override val isNotYetValid: Boolean
        get() = jwsNotYetValidError != null || credentialNotYetValidError != null
}

