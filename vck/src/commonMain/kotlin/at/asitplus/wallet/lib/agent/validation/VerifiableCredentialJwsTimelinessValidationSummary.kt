package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class VerifiableCredentialJwsTimelinessValidationSummary(
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