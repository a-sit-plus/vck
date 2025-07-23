package at.asitplus.wallet.lib.agent.validation.common

import kotlin.time.Instant

data class EntityExpiredError(
    val expirationTime: Instant,
    val earliestAcceptedExpirationTime: Instant,
)