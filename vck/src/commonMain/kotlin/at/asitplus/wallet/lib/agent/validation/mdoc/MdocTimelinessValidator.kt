package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.iso.IssuerSigned
import io.github.aakira.napier.Napier

class MdocTimelinessValidator(
    private val mobileSecurityObjectTimelinessValidator: MobileSecurityObjectTimelinessValidator = MobileSecurityObjectTimelinessValidator(),
) {
    operator fun invoke(
        issuerSigned: IssuerSigned,
        timeScope: TimeScope,
    ) = timeScope {
        MdocTimelinessValidationDetails(
            evaluationTime = now,
            msoTimelinessValidationSummary = issuerSigned.issuerAuth.payload?.let {
                mobileSecurityObjectTimelinessValidator(it, timeScope)
            }
        ).also {
            if(it.isTimely) {
                Napier.d("ISO Cred $it is timely")
            }
        }
    }
}

