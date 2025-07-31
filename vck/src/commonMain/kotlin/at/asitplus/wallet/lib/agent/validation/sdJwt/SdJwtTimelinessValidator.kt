package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.github.aakira.napier.Napier

class SdJwtTimelinessValidator {
    operator fun invoke(
        sdJwt: VerifiableCredentialSdJwt,
        timeScope: TimeScope,
    ) = timeScope {
        SdJwtTimelinessValidationDetails(
            evaluationTime = now,
            jwsExpiredError = with(sdJwt.expiration) {
                if (this != null && this.isTooEarly()) {
                    Napier.w("exp invalid: $this, now is $now")
                    EntityExpiredError(
                        expirationTime = this,
                        earliestAcceptedExpirationTime = earliestTime,
                    )
                } else null
            },
            jwsNotYetValidError = with(sdJwt.notBefore) {
                if (this != null && this.isTooLate()) {
                    Napier.w("nbf invalid: $this, now is $now")
                    EntityNotYetValidError(
                        notBeforeTime = this,
                        latestAcceptedNotBeforeTime = latestTime,
                    )
                } else null
            }
        ).also {
            if (it.isTimely) {
                Napier.d("SD-JWT is timely")
            }
        }
    }
}
