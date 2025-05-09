package at.asitplus.wallet.lib.agent.validation.vcJws

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

    operator fun invoke(vcJws: VerifiableCredentialJws): VcJwsTimelinessValidationDetails {
        val now = clock.now()
        val earliestAcceptedExpirationTime = (now - timeLeeway)
        val latestAcceptedNotBeforeTime = (now + timeLeeway)

        return VcJwsTimelinessValidationDetails(
            evaluationTime = now,
            jwsExpiredError = if (vcJws.expiration != null && vcJws.expiration < earliestAcceptedExpirationTime) {
                Napier.w("exp invalid: ${vcJws.expiration}, now is $now")
                EntityExpiredError(
                    expirationTime = vcJws.expiration,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            credentialExpiredError = if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < earliestAcceptedExpirationTime) {
                Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is $now")
                EntityExpiredError(
                    expirationTime = vcJws.vc.expirationDate,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            jwsNotYetValidError = if (vcJws.notBefore > latestAcceptedNotBeforeTime) {
                Napier.w("nbf invalid: ${vcJws.notBefore}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = vcJws.notBefore,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
            credentialNotYetValidError = if (vcJws.vc.issuanceDate > latestAcceptedNotBeforeTime) {
                Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = vcJws.vc.issuanceDate,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
        ).also {
            if (it.isSuccess) {
                Napier.d("VC is timely")
            }
        }
    }
}
