package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.IssuerSigned
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLQuery
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
            val signedVcJws: JwsCompactTyped<VerifiableCredentialJws>,
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

    /**
     * Creates a mapping from the input descriptors of the presentation definition to matching
     * credentials and the fields that would need to be disclosed.
     *
     * @param fallbackFormatHolder format holder to be used in case there is no format holder in a
     *  given presentation definition and the input descriptor.
     *  This will mostly resolve to be the same `clientMetadata.vpFormats`.
     * @param pathAuthorizationValidator Provides the user of this library with a way to enforce
     *  authorization rules on attribute credentials that are to be disclosed.
     * @param filterByIds filter the list of possible credentials by the provided IDs
     */
    @Deprecated("Use matchPresentationRequestAgainstCredentialStore instead")
    suspend fun matchInputDescriptorsAgainstCredentialStoreV2(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder? = null,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
        filterByIds: Collection<String>? = null
    ): KmmResult<HolderPresentationExchangeQueryMatchingResult<SubjectCredentialStore.StoreEntry>>

    /**
     * Matches every document in [deviceRequest] against the credential store. Results preserve `docRequests` order
     * and contain only credentials that provide every requested namespace and data element. Reader authentication is
     * transport-specific and is not validated here.
     *
     * @param deviceRequest from the ISO Device Retrieval Request
     * @param filterByIds filter the list of possible credentials by the provided IDs
     */
    @Deprecated(
        "Use matchPresentationRequestAgainstCredentialStore instead",
        ReplaceWith(
            "matchPresentationRequestAgainstCredentialStore(CredentialPresentationRequest.IsoDeviceRetrieval(deviceRequest), filterByIds)",
            "at.asitplus.wallet.lib.data.CredentialPresentationRequest",
        ),
    )
    suspend fun matchDeviceRetrievalAgainstCredentialStore(
        deviceRequest: DeviceRequest,
        filterByIds: Collection<String>? = null
    ): KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<SubjectCredentialStore.StoreEntry>>

    /**
     * Evaluates a given input descriptor against a store entry.
     *
     * @param fallbackFormatHolder format holder to be used in case there is no format holder in the input descriptor.
     *  This will mostly be some `presentationDefinition.formats ?: clientMetadata.vpFormats`
     * @param pathAuthorizationValidator Provides the user of this library with a way to enforce
     *  authorization rules on attribute credentials that are to be disclosed.
     * @return for each constraint field a set of matching nodes or null
     */
    @Deprecated("Use matchPresentationRequestAgainstCredentialStore instead")
    fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>>

    /**
     * Creates a mapping from the DCQL credential query identifiers of the DCQL query to matching
     * credentials and the claims credential set queries to be satisfied.
     *
     * @param filterByIds filter the list of possible credentials by the provided IDs
     */
    @Deprecated(
        "Use matchPresentationRequestAgainstCredentialStore instead",
        ReplaceWith(
            "matchPresentationRequestAgainstCredentialStore(CredentialPresentationRequest.DCQLRequest(dcqlQuery), filterByIds)",
            "at.asitplus.wallet.lib.data.CredentialPresentationRequest",
        ),
    )
    suspend fun matchDCQLQueryAgainstCredentialStoreV2(
        dcqlQuery: DCQLQuery,
        filterByIds: Collection<String>? = null
    ): KmmResult<HolderDCQLQueryMatchingResult<SubjectCredentialStore.StoreEntry>>

}
