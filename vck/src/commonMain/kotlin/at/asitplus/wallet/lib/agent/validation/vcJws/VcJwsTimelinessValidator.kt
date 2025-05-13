package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.agent.validation.TimeScope.Companion.timeScoped
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class VcJwsTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
) {

    operator fun invoke(vcJws: VerifiableCredentialJws) = timeScoped(clock, timeLeeway) {
        VcJwsTimelinessValidationDetails(
            evaluationTime = now,
            jwsExpiredError = if (vcJws.expiration != null && vcJws.expiration.isTooEarly()) {
                Napier.w("exp invalid: ${vcJws.expiration}, now is $now")
                EntityExpiredError(
                    expirationTime = vcJws.expiration,
                    earliestAcceptedExpirationTime = earliestTime,
                )
            } else null,
            credentialExpiredError = if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate.isTooEarly()) {
                Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is $now")
                EntityExpiredError(
                    expirationTime = vcJws.vc.expirationDate,
                    earliestAcceptedExpirationTime = earliestTime,
                )
            } else null,
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
            if (it.isSuccess) {
                Napier.d("VC is timely")
            }
        }
    }
}
