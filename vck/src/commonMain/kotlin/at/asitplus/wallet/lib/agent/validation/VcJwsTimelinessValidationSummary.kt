package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class VcJwsTimelinessValidationSummary(
    val evaluationTime: Instant,
    val jwsExpiredError: JwsExpiredError?,
    val credentialExpiredError: CredentialExpiredError?,
    val jwsNotYetValidError: JwsNotYetValidError?,
    val credentialNotYetValidError: CredentialNotYetValidError?,
) {
    val isSuccess = listOf(
        jwsExpiredError,
        credentialExpiredError,
        jwsNotYetValidError,
        credentialNotYetValidError,
    ).all { it == null }

    data class CredentialExpiredError(
        val expirationDate: Instant,
        val earliestAcceptedExpirationDate: Instant,
    )

    data class CredentialNotYetValidError(
        val issuanceDate: Instant,
        val latestAcceptedNotBeforeTime: Instant,
    )
}

