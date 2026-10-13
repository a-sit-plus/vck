package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.github.aakira.napier.Napier

object SdJwtTimelinessValidator {
    operator fun invoke(
        sdJwt: VerifiableCredentialSdJwt,
        timeScope: TimeScope,
    ) = timeScope {
        SdJwtTimelinessValidationDetails(
            evaluationTime = now,
            jwsExpiredError = with(sdJwt.expiration) {
                if (this != null && this.isTooEarly()) {
                    EntityExpiredError(
                        expirationTime = this,
                        earliestAcceptedExpirationTime = earliestTime,
                    )
                } else null
            },
            jwsNotYetValidError = with(sdJwt.notBefore) {
                if (this != null && this.isTooLate()) {
                    EntityNotYetValidError(
                        notBeforeTime = this,
                        latestAcceptedNotBeforeTime = latestTime,
                    )
                } else null
            }
        )
    }
}
