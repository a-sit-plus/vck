package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class MobileSecurityObjectTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
) {
    operator fun invoke(mobileSecurityObject: MobileSecurityObject) = TimeScope(clock.now(), timeLeeway).run {
        MobileSecurityObjectTimelinessValidationSummary(
            evaluationTime = now,
            mdocExpiredError = if (mobileSecurityObject.validityInfo.validUntil.isTooEarly()) {
                Napier.w("MSO is expired: ${mobileSecurityObject.validityInfo.validUntil}, now is $now")
                EntityExpiredError(
                    expirationTime = mobileSecurityObject.validityInfo.validUntil,
                    earliestAcceptedExpirationTime = earliestTime,
                )
            } else null,
            mdocNotYetValidError = if (mobileSecurityObject.validityInfo.validFrom.isTooLate()) {
                Napier.w("MSO is not yet valid: ${mobileSecurityObject.validityInfo.validFrom}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = mobileSecurityObject.validityInfo.validFrom,
                    latestAcceptedNotBeforeTime = latestTime,
                )
            } else null,
        ).also {
            if (it.isSuccess) {
                Napier.d("MSO is timely")
            }
        }
    }
}

