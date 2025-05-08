package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class CredentialTimelinessValidator(
    private val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    val vcJwsTimelinessValidator: VcJwsTimelinessValidator = VcJwsTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
    val sdJwtTimelinessValidator: SdJwtTimelinessValidator = SdJwtTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
    val mdocTimelinessValidator: MdocTimelinessValidator = MdocTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock
    ),
) {
    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
        is SubjectCredentialStore.StoreEntry.Iso -> invoke(CredentialWrapper.Mdoc(storeEntry.issuerSigned))
        is SubjectCredentialStore.StoreEntry.SdJwt -> invoke(CredentialWrapper.SdJwt(storeEntry.sdJwt))
        is SubjectCredentialStore.StoreEntry.Vc -> invoke(CredentialWrapper.VcJws(storeEntry.vc))
    }

    operator fun invoke(credentialWrapper: CredentialWrapper): CredentialTimelinessValidationSummary {
        return when (credentialWrapper) {
            is CredentialWrapper.Mdoc -> CredentialTimelinessValidationSummary.Mdoc(
                credential = credentialWrapper,
                mdocTimelinessValidator.invoke(credentialWrapper.issuerSigned),
            )

            is CredentialWrapper.SdJwt -> CredentialTimelinessValidationSummary.SdJwt(
                credential = credentialWrapper,
                sdJwtTimelinessValidator(credentialWrapper.sdJwt),
            )

            is CredentialWrapper.VcJws -> CredentialTimelinessValidationSummary.VcJws(
                credential = credentialWrapper,
                vcJwsTimelinessValidator(vcJws = credentialWrapper.verifiableCredentialJws),
            )
        }
    }
}

