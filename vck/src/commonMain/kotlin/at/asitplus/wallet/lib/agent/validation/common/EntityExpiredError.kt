package at.asitplus.wallet.lib.agent.validation.common

import kotlinx.datetime.Instant

data class EntityExpiredError(
    val expirationTime: Instant,
    val earliestAcceptedExpirationTime: Instant,
)