package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
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
    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry.Iso) = MdocTimelinessValidationSummary(
        msoTimelinessValidationSummary = storeEntry.issuerSigned.issuerAuth.payload?.let {
            mobileSecurityObjectTimelinessValidator(it)
        }?.also {
            if(it.isSuccess) {
                Napier.d("Verifying ISO Cred $it")
            }
        }
    )
}

