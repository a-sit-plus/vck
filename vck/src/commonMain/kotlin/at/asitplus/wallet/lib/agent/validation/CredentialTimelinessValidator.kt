package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned
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
    operator fun invoke(issuerSigned: IssuerSigned) = CredentialTimelinessValidationSummary.Mdoc(
        mdocTimelinessValidator(issuerSigned),
    )

    operator fun invoke(sdJwt: VerifiableCredentialSdJwt) = CredentialTimelinessValidationSummary.SdJwt(
        sdJwtTimelinessValidator(sdJwt),
    )

    operator fun invoke(vcJws: VerifiableCredentialJws) = CredentialTimelinessValidationSummary.VcJws(
        vcJwsTimelinessValidator(vcJws = vcJws),
    )

    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
        is SubjectCredentialStore.StoreEntry.Iso -> invoke(storeEntry)
        is SubjectCredentialStore.StoreEntry.SdJwt -> invoke(storeEntry)
        is SubjectCredentialStore.StoreEntry.Vc -> invoke(storeEntry)
    }
    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry.Vc) = invoke(storeEntry.vc)
    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry.SdJwt) = invoke(storeEntry.sdJwt)
    operator fun invoke(storeEntry: SubjectCredentialStore.StoreEntry.Iso) = invoke(storeEntry.issuerSigned)


    operator fun invoke(credentialWrapper: CredentialWrapper): CredentialTimelinessValidationSummary = when (credentialWrapper) {
        is CredentialWrapper.Mdoc -> invoke(credentialWrapper.issuerSigned)
        is CredentialWrapper.SdJwt -> invoke(credentialWrapper.sdJwt)
        is CredentialWrapper.VcJws -> invoke(credentialWrapper.verifiableCredentialJws)
    }
}

