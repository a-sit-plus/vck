package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

interface TimelinessIndicator {
    val evaluationTime: Instant

    val isExpired: Boolean

    val isNotYetValid: Boolean

    val isTimely: Boolean
        get() = !isNotYetValid && !isExpired
}