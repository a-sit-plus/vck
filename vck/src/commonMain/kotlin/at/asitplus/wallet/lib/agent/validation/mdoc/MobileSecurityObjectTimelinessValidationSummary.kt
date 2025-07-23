package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.validation.TimelinessIndicator
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import kotlin.time.Instant

data class MobileSecurityObjectTimelinessValidationSummary(
    override val evaluationTime: Instant,
    val mdocExpiredError: EntityExpiredError?,
    val mdocNotYetValidError: EntityNotYetValidError?,
) : TimelinessIndicator {
    override val isExpired: Boolean
        get() = mdocExpiredError != null

    override val isNotYetValid: Boolean
        get() = mdocNotYetValidError != null
}