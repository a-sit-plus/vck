package at.asitplus.wallet.lib.agent.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

data class CredentialTimelinessValidator(
    /**
     * @param timeLeeway specifies tolerance for expiration and start of validity of credentials.
     * A credential that expired at most `timeLeeway` ago is not yet considered expired.
     * A credential that is valid in at most `timeLeeway` is already considered valid.
     */
    private val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    val vcJwsTimelinessValidator: VcJwsTimelinessValidator = VcJwsTimelinessValidator(),
    val sdJwtTimelinessValidator: SdJwtTimelinessValidator = SdJwtTimelinessValidator(),
    val mdocTimelinessValidator: MdocTimelinessValidator = MdocTimelinessValidator(),
) {
    operator fun invoke(issuerSigned: IssuerSigned) = CredentialTimelinessValidationSummary.Mdoc(
        mdocTimelinessValidator(issuerSigned, timeScope = TimeScope(clock.now(), timeLeeway)),
    )

    operator fun invoke(sdJwt: VerifiableCredentialSdJwt) = CredentialTimelinessValidationSummary.SdJwt(
        sdJwtTimelinessValidator(sdJwt, timeScope = TimeScope(clock.now(), timeLeeway)),
    )

    operator fun invoke(vcJws: VerifiableCredentialJws) = CredentialTimelinessValidationSummary.VcJws(
        vcJwsTimelinessValidator(vcJws, timeScope = TimeScope(clock.now(), timeLeeway)),
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

