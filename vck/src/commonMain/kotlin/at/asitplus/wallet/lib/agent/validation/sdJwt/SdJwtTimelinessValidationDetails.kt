package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.TimelinessIndicator
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlin.time.Instant

data class SdJwtTimelinessValidationDetails(
    override val evaluationTime: Instant,
    val jwsExpiredError: EntityExpiredError?,
    val jwsNotYetValidError: EntityNotYetValidError?,
): TimelinessIndicator {
    override val isExpired: Boolean
        get() = jwsExpiredError != null

    override val isNotYetValid: Boolean
        get() = jwsNotYetValidError != null
}