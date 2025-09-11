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
                EntityExpiredError(
                    expirationTime = mobileSecurityObject.validityInfo.validUntil,
                    earliestAcceptedExpirationTime = earliestTime,
                )
            } else null,
            mdocNotYetValidError = if (mobileSecurityObject.validityInfo.validFrom.isTooLate()) {
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

