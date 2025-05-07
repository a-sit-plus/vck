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
    private val earliestAcceptedExpirationTime = (clock.now() - timeLeeway)
    private val latestAcceptedNotBeforeTime = (clock.now() + timeLeeway)

    operator fun invoke(vcJws: VerifiableCredentialJws) = VcJwsTimelinessValidationSummary(
        jwsExpiredError = if (vcJws.expiration != null && vcJws.expiration < earliestAcceptedExpirationTime) {
            Napier.w("exp invalid: ${vcJws.expiration}, now is ${clock.now()}")
            VcJwsTimelinessValidationSummary.JwsExpiredError(
                expirationTime = vcJws.expiration,
                earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
            )
        } else null,
        credentialExpiredError = if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < earliestAcceptedExpirationTime) {
            Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is ${clock.now()}")
            VcJwsTimelinessValidationSummary.CredentialExpiredError(
                expirationDate = vcJws.vc.expirationDate,
                earliestAcceptedExpirationDate = earliestAcceptedExpirationTime,
            )
        } else null,
        jwsNotYetValidError = if (vcJws.notBefore > latestAcceptedNotBeforeTime) {
            Napier.w("nbf invalid: ${vcJws.notBefore}, now is ${clock.now()}")
            VcJwsTimelinessValidationSummary.JwsNotYetValidError(
                notBeforeTime = vcJws.notBefore,
                latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
            )
        } else null,
        credentialNotYetValidError = if (vcJws.vc.issuanceDate > latestAcceptedNotBeforeTime) {
            Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is ${clock.now()}")
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
