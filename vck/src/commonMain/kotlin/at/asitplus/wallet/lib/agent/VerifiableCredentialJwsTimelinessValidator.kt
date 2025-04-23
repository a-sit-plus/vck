package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.DurationUnit
import kotlin.time.toDuration

data class VerifiableCredentialJwsTimelinessValidator(
    val timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
) {
    val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)

    fun validate(vcJws: VerifiableCredentialJws): ValidationSummary {
        val earliestAcceptedExpirationTime = (clock.now() - timeLeeway)
        val latestAcceptedNotBeforeTime = (clock.now() + timeLeeway)

        return ValidationSummary(
            jwsExpiredError = if (vcJws.expiration != null && vcJws.expiration < earliestAcceptedExpirationTime) {
                Napier.w("exp invalid: ${vcJws.expiration}, now is ${clock.now()}")
                JwsExpiredError(
                    expirationTime = vcJws.expiration,
                    earliestAcceptedExpirationTime = earliestAcceptedExpirationTime,
                )
            } else null,
            credentialExpiredError = if (vcJws.vc.expirationDate != null && vcJws.vc.expirationDate < earliestAcceptedExpirationTime) {
                Napier.w("expirationDate invalid: ${vcJws.vc.expirationDate}, now is ${clock.now()}")
                CredentialExpiredError(
                    expirationDate = vcJws.vc.expirationDate,
                    earliestAcceptedExpirationDate = earliestAcceptedExpirationTime,
                )
            } else null,
            jwsNotYetValidError = if (vcJws.notBefore > latestAcceptedNotBeforeTime) {
                Napier.w("nbf invalid: ${vcJws.notBefore}, now is ${clock.now()}")
                JwsNotYetValidError(
                    notBeforeTime = vcJws.notBefore,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
            credentialNotYetValidError = if (vcJws.vc.issuanceDate > latestAcceptedNotBeforeTime) {
                Napier.w("issuanceDate invalid: ${vcJws.vc.issuanceDate}, now is ${clock.now()}")
                CredentialNotYetValidError(
                    issuanceDate = vcJws.vc.issuanceDate,
                    latestAcceptedNotBeforeTime = latestAcceptedNotBeforeTime,
                )
            } else null,
        ).also {
            if (!it.containsErrors) {
                Napier.d("VC is timely")
            }
        }
    }

    inner class ValidationSummary(
        val jwsExpiredError: JwsExpiredError?,
        val credentialExpiredError: CredentialExpiredError?,
        val jwsNotYetValidError: JwsNotYetValidError?,
        val credentialNotYetValidError: CredentialNotYetValidError?,
    ) {
        val containsErrors = listOf(
            jwsExpiredError,
            credentialExpiredError,
            jwsNotYetValidError,
            credentialNotYetValidError,
        ).any { it != null }
    }

    data class JwsExpiredError(
        val expirationTime: Instant,
        val earliestAcceptedExpirationTime: Instant,
    )

    data class CredentialExpiredError(
        val expirationDate: Instant,
        val earliestAcceptedExpirationDate: Instant,
    )

    data class JwsNotYetValidError(
        val notBeforeTime: Instant,
        val latestAcceptedNotBeforeTime: Instant,
    )

    data class CredentialNotYetValidError(
        val issuanceDate: Instant,
        val latestAcceptedNotBeforeTime: Instant,
    )
}