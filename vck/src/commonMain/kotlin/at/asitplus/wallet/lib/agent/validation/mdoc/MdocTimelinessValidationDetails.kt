package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.validation.TimelinessIndicator
import kotlinx.datetime.Instant

data class MdocTimelinessValidationDetails(
    override val evaluationTime: Instant,
    val msoTimelinessValidationSummary: MobileSecurityObjectTimelinessValidationSummary?,
) : TimelinessIndicator {
    override val isExpired: Boolean
        get() = msoTimelinessValidationSummary?.isExpired ?: false

    override val isNotYetValid: Boolean
        get() = msoTimelinessValidationSummary?.isNotYetValid ?: false
}

