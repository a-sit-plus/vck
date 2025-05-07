package at.asitplus.wallet.lib.agent.validation.common

import kotlinx.datetime.Instant

data class EntityNotYetValidError(
    val notBeforeTime: Instant,
    val latestAcceptedNotBeforeTime: Instant,
)