package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import io.github.aakira.napier.Napier

class MobileSecurityObjectTimelinessValidator {
    operator fun invoke(
        mobileSecurityObject: MobileSecurityObject,
        timeScope: TimeScope,
    ) = timeScope {
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
            if (it.isTimely) {
                Napier.d("MSO is timely")
            }
        }
    }
}

