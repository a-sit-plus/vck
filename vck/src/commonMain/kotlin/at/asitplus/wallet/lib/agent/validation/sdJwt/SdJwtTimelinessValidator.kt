package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class SdJwtTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
) {
    operator fun invoke(sdJwt: VerifiableCredentialSdJwt): SdJwtTimelinessValidationSummary {
        val now = clock.now()
        val earliestAcceptedExpirationTime = (now - timeLeeway)
        val latestAcceptedNotBeforeTime = (now + timeLeeway)

        return SdJwtTimelinessValidationSummary(
            evaluationTime = now,
            jwsExpiredError = if (sdJwt.expiration != null && sdJwt.expiration < earliestAcceptedExpirationTime) {
                Napier.w("exp invalid: ${sdJwt.expiration}, now is $now")
                EntityExpiredError(
                    expirationTime = sdJwt.expiration,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            jwsNotYetValidError = if (sdJwt.notBefore != null && sdJwt.notBefore > latestAcceptedNotBeforeTime) {
                Napier.w("nbf invalid: ${sdJwt.notBefore}, now is $now")
                EntityNotYetValidError(
                    notBeforeTime = sdJwt.notBefore,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
        ).also {
            if (it.isSuccess) {
                Napier.d("SD-JWT is timely")
            }
        }
    }
}
