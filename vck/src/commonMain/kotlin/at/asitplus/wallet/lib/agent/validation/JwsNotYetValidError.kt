package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class JwsNotYetValidError(
    val notBeforeTime: Instant,
    val latestAcceptedNotBeforeTime: Instant,
)