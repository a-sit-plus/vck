package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.iso.IssuerSigned

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

    @Deprecated("Use keyMaterial instead", ReplaceWith("keyMaterial"))
    val keyPair: KeyMaterial
        get() = keyMaterial

    sealed class StoreCredentialInput {
        data class Vc(
            val vcJws: String,
            val scheme: ConstantIndex.CredentialScheme,
        ) : StoreCredentialInput()

        data class SdJwt(
            val vcSdJwt: String,
            val scheme: ConstantIndex.CredentialScheme,
        ) : StoreCredentialInput()

        data class Iso(
            val issuerSigned: IssuerSigned,
            val scheme: ConstantIndex.CredentialScheme,
        ) : StoreCredentialInput()
    }

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     */
    suspend fun storeCredential(credential: StoreCredentialInput): KmmResult<SubjectCredentialStore.StoreEntry>

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

    /**
     * Creates a mapping from the input descriptors of the presentation definition to matching
     * credentials and the fields that would need to be disclosed.
     *
     * @param fallbackFormatHolder format holder to be used in case there is no format holder in a
     *  given presentation definition and the input descriptor.
     *  This will mostly resolve to be the same `clientMetadata.vpFormats`.
     * @param pathAuthorizationValidator Provides the user of this library with a way to enforce
     *  authorization rules on attribute credentials that are to be disclosed.
     * @param filterById filter the list of possible credentials by the provided ID
     */
    suspend fun matchInputDescriptorsAgainstCredentialStore(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder? = null,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
        filterById: String? = null
    ): KmmResult<Map<String, InputDescriptorMatches>>

    /**
     * Evaluates a given input descriptor against a store entry.
     *
     * @param fallbackFormatHolder format holder to be used in case there is no format holder in the input descriptor.
     *  This will mostly be some `presentationDefinition.formats ?: clientMetadata.vpFormats`
     * @param pathAuthorizationValidator Provides the user of this library with a way to enforce
     *  authorization rules on attribute credentials that are to be disclosed.
     * @return for each constraint field a set of matching nodes or null
     */
    fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>>

    /**
     * Creates a mapping from the dcql credential query identifiers of the dcql query to matching
     * credentials and the claims credential set queries to be satisfied.
     *
     * @param filterById filter the list of possible credentials by the provided ID
     */
    suspend fun matchDCQLQueryAgainstCredentialStore(
        dcqlQuery: DCQLQuery,
        filterById: String? = null
    ): KmmResult<DCQLQueryResult<SubjectCredentialStore.StoreEntry>>
}

