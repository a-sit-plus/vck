package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class CredentialTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    private val tokenStatusResolver: TokenStatusResolver,
    private val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator = VerifiableCredentialJwsTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
) {
    suspend operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry) = CredentialTimelinessValidationSummary(
        tokenStatus = when (storeEntry) {
            is SubjectCredentialStore.StoreEntry.Iso -> storeEntry.issuerSigned.issuerAuth.payload?.status
            is SubjectCredentialStore.StoreEntry.SdJwt -> storeEntry.sdJwt.credentialStatus
            is SubjectCredentialStore.StoreEntry.Vc -> storeEntry.vc.vc.credentialStatus
        }?.let {
            tokenStatusResolver(it)
        },
        timelinessValidationSummaryDetails = when (storeEntry) {
            is SubjectCredentialStore.StoreEntry.Iso -> CredentialTimelinessValidationSummaryDetails.MdocCredential(
                storeEntry = storeEntry,
                isSuccess = true
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> CredentialTimelinessValidationSummaryDetails.SdJwtCredential(
                storeEntry = storeEntry,
                isSuccess = true
            )

            is SubjectCredentialStore.StoreEntry.Vc -> CredentialTimelinessValidationSummaryDetails.VerifiableCredential(
                storeEntry = storeEntry,
                verifiableCredentialJwsTimelinessValidator(vcJws = storeEntry.vc),
            )
        }
    ).also {
        if (it.isSuccess) {
            Napier.d("VC is timely")
        }
    }
}

