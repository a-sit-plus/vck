package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class CredentialTimelinessValidator(
    val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    private val tokenStatusResolver: TokenStatusResolver = TokenStatusResolver {
        KmmResult.success(TokenStatus.Valid)
    },
    private val vcJwsTimelinessValidator: VcJwsTimelinessValidator = VcJwsTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
    private val sdJwtTimelinessValidator: SdJwtTimelinessValidator = SdJwtTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
    private val mdocTimelinessValidator: MdocTimelinessValidator = MdocTimelinessValidator(
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
                summary = mdocTimelinessValidator.invoke(storeEntry),
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> CredentialTimelinessValidationSummaryDetails.SdJwtCredential(
                storeEntry = storeEntry,
                sdJwtTimelinessValidator(storeEntry.sdJwt),
            )

            is SubjectCredentialStore.StoreEntry.Vc -> CredentialTimelinessValidationSummaryDetails.VerifiableCredential(
                storeEntry = storeEntry,
                vcJwsTimelinessValidator(vcJws = storeEntry.vc),
            )
        }
    ).also {
        if (it.isSuccess) {
            Napier.d("VC is timely")
        }
    }
}

