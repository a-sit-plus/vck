package at.asitplus.wallet.lib.agent.validation.common

import kotlin.time.Instant

data class EntityNotYetValidError(
    val notBeforeTime: Instant,
    val latestAcceptedNotBeforeTime: Instant,
)