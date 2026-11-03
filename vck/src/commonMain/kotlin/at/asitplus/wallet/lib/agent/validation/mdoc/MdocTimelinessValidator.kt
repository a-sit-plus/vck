package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.validation.TimeScope

object MdocTimelinessValidator {
    operator fun invoke(
        issuerSigned: IssuerSigned,
        timeScope: TimeScope,
    ) = timeScope {
        MdocTimelinessValidationDetails(
            evaluationTime = now,
            msoTimelinessValidationSummary = issuerSigned.issuerAuth.payload?.let {
                MobileSecurityObjectTimelinessValidator(it, timeScope)
            }
        )
    }
}
