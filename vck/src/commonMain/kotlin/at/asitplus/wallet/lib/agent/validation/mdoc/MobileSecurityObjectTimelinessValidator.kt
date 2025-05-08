package at.asitplus.wallet.lib.agent.validation.mdoc

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
    operator fun invoke(mobileSecurityObject: MobileSecurityObject): MobileSecurityObjectTimelinessValidationSummary {
        val now = clock.now()
        val earliestAcceptedExpirationTime = (now - timeLeeway)
        val latestAcceptedNotBeforeTime = (now + timeLeeway)

        return MobileSecurityObjectTimelinessValidationSummary(
            evaluationTime = now,
            mdocExpiredError = if (mobileSecurityObject.validityInfo.validUntil < earliestAcceptedExpirationTime) {
                Napier.w("MSO is expired: ${mobileSecurityObject.validityInfo.validUntil}, now is $now")
                EntityExpiredError(
                    expirationTime = mobileSecurityObject.validityInfo.validUntil,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            mdocNotYetValidError = if (mobileSecurityObject.validityInfo.validFrom > latestAcceptedNotBeforeTime) {
                Napier.w("MSO is not yet valid: ${mobileSecurityObject.validityInfo.validFrom}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = mobileSecurityObject.validityInfo.validFrom,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
        ).also {
            if (it.isSuccess) {
                Napier.d("MSO is timely")
            }
        }
    }
}
