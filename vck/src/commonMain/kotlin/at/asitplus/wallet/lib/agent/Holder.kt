package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.KmmResult
import at.asitplus.iso.IssuerSigned
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.SdJwtSigned

/**
 * Summarizes operations for a Holder in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can store Verifiable Credentials, and create a Verifiable Presentation out of the stored credentials
 */
interface Holder {

    /**
     * The public key for this agent, i.e. the "holder key" that the credentials get bound to.
     */
    val keyMaterial: KeyMaterial

    sealed class StoreCredentialInput {
        data class Vc(
            val signedVcJws: JwsCompactTyped<VerifiableCredentialJws, JwsHeader>,
            val vcJws: String,
            val scheme: VcJwtCredentialScheme,
        ) : StoreCredentialInput()

        data class SdJwt(
            val signedSdJwtVc: SdJwtSigned,
            val vcSdJwt: String,
            val scheme: SdJwtCredentialScheme,
        ) : StoreCredentialInput()

        data class Iso(
            val issuerSigned: IssuerSigned,
            val scheme: IsoMdocCredentialScheme,
        ) : StoreCredentialInput()
    }

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     */
    suspend fun storeCredential(
        credential: StoreCredentialInput,
        renewalInfo: CredentialRenewalInfo? = null
    ): KmmResult<SubjectCredentialStore.StoreEntry>

    /**
     * Gets a list of all stored credentials, with a revocation status.
     */
    suspend fun getCredentials(): Collection<SubjectCredentialStore.StoreEntry>?

    /**
     * Creates [PresentationResponseParameters] as specified using the parameter [credentialPresentation]
     *
     * Fails in case the submission is not a valid submission.
     */
    suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters>

    /**
     * Creates [PresentationResponseParameters] using the default submission.
     *
     * Fails in case the default submission is not a valid submission.
     */
    suspend fun createDefaultPresentation(
        request: PresentationRequestParameters,
        credentialPresentationRequest: CredentialPresentationRequest,
    ): KmmResult<PresentationResponseParameters>

    /** Matches any supported presentation request while preserving its request-specific result type. */
    suspend fun matchPresentationRequestAgainstCredentialStore(
        presentationRequest: CredentialPresentationRequest,
        filterByIds: Collection<String>? = null,
    ): KmmResult<CredentialMatchingResult<SubjectCredentialStore.StoreEntry>>

}
