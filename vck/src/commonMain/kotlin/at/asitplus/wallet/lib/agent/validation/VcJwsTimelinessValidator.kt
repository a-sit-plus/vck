package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class VcJwsTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
) {

    operator fun invoke(vcJws: VerifiableCredentialJws): VcJwsTimelinessValidationSummary {
        val now = clock.now()
        val earliestAcceptedExpirationTime = (now - timeLeeway)
        val latestAcceptedNotBeforeTime = (now + timeLeeway)

        return VcJwsTimelinessValidationSummary(
            evaluationTime = now,
            jwsExpiredError = if (vcJws.expiration != null && vcJws.expiration < earliestAcceptedExpirationTime) {
                Napier.w("exp invalid: ${vcJws.expiration}, now is $now")
                JwsExpiredError(
                    expirationTime = vcJws.expiration,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            credentialExpiredError = if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < earliestAcceptedExpirationTime) {
                Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is $now")
                VcJwsTimelinessValidationSummary.CredentialExpiredError(
                    expirationDate = vcJws.vc.expirationDate,
                    earliestAcceptedExpirationDate = earliestAcceptedExpirationTime,
                )
            } else null,
            jwsNotYetValidError = if (vcJws.notBefore > latestAcceptedNotBeforeTime) {
                Napier.w("nbf invalid: ${vcJws.notBefore}, now is $now")
                JwsNotYetValidError(
                    notBeforeTime = vcJws.notBefore,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
            credentialNotYetValidError = if (vcJws.vc.issuanceDate > latestAcceptedNotBeforeTime) {
                Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is $now")
                VcJwsTimelinessValidationSummary.CredentialNotYetValidError(
                    issuanceDate = vcJws.vc.issuanceDate,
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
