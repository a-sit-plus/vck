package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class JwsExpiredError(
    val expirationTime: Instant,
    val earliestAcceptedExpirationTime: Instant,
)