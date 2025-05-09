package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.iso.IssuerSigned
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration

class MdocTimelinessValidator(
    clock: Clock,
    timeLeeway: Duration,
    private val mobileSecurityObjectTimelinessValidator: MobileSecurityObjectTimelinessValidator = MobileSecurityObjectTimelinessValidator(
        clock = clock,
        timeLeeway = timeLeeway,
    ),
) {
    operator fun invoke(issuerSigned: IssuerSigned) = MdocTimelinessValidationDetails(
        msoTimelinessValidationSummary = issuerSigned.issuerAuth.payload?.let {
            mobileSecurityObjectTimelinessValidator(it)
        }
    ).also {
        if(it.isSuccess) {
            Napier.d("ISO Cred $it is timely")
        }
    }
}

