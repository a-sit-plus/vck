package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

class VcJwsTimelinessValidator {
    operator fun invoke(
        vcJws: VerifiableCredentialJws,
        timeScope: TimeScope,
    ) = timeScope {
        VcJwsTimelinessValidationDetails(
            evaluationTime = now,
            jwsExpiredError = with(vcJws.expiration) {
                if (this != null && this.isTooEarly()) {
                    Napier.w("exp invalid: $this, now is $now")
                    EntityExpiredError(
                        expirationTime = this,
                        earliestAcceptedExpirationTime = earliestTime,
                    )
                } else null
            },
            credentialExpiredError = with(vcJws.vc.expirationDate) {
                if (this != null && this.isTooEarly()) {
                    Napier.w("expirationDate invalid: ${this}, now is $now")
                    EntityExpiredError(
                        expirationTime = this,
                        earliestAcceptedExpirationTime = earliestTime,
                    )
                } else null
            },
            jwsNotYetValidError = if (vcJws.notBefore.isTooLate()) {
                Napier.w("nbf invalid: ${vcJws.notBefore}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = vcJws.notBefore,
                    latestAcceptedNotBeforeTime = latestTime,
                )
            } else null,
            credentialNotYetValidError = if (vcJws.vc.issuanceDate.isTooLate()) {
                Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = vcJws.vc.issuanceDate,
                    latestAcceptedNotBeforeTime = latestTime,
                )
            } else null,
        ).also {
            if (it.isTimely) {
                Napier.d("VC is timely")
            }
        }
    }
}
