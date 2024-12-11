package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.dif.*
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSigned
import kotlinx.serialization.Serializable

@Serializable
data class CredentialSubmission(
    val credential: SubjectCredentialStore.StoreEntry,
    val disclosedAttributes: Collection<NormalizedJsonPath>,
)

typealias InputDescriptorMatches = Map<SubjectCredentialStore.StoreEntry, Map<ConstraintField, NodeList>>

/**
 * Summarizes operations for a Holder in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can store Verifiable Credentials, and create a Verifiable Presentation out of the stored credentials
 */
interface Holder {

    /**
     * The public key for this agent, i.e. the "holder key" that the credentials get bound to.
     */
    val keyPair: KeyMaterial

    /**
     * Sets the revocation list ot use for further processing of Verifiable Credentials
     *
     * @return `true` if the revocation list has been validated and set, `false` otherwise
     */
    fun setRevocationList(it: String): Boolean

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
     *
     * Note: Revocation credentials should not be stored, but set with [setRevocationList].
     */
    suspend fun storeCredential(credential: StoreCredentialInput): KmmResult<StoredCredential>

    /**
     * Gets a list of all stored credentials, with a revocation status.
     *
     * Note that the revocation status may be [Validator.RevocationStatus.UNKNOWN] if no revocation list
     * has been set with [setRevocationList]
     */
    suspend fun getCredentials(): Collection<StoredCredential>?

    sealed class StoredCredential(
        open val storeEntry: SubjectCredentialStore.StoreEntry,
        val status: Validator.RevocationStatus,
    ) {
        class Vc(
            override val storeEntry: SubjectCredentialStore.StoreEntry.Vc,
            status: Validator.RevocationStatus
        ) : StoredCredential(
            storeEntry = storeEntry, status = status
        )

        class SdJwt(
            override val storeEntry: SubjectCredentialStore.StoreEntry.SdJwt,
            status: Validator.RevocationStatus
        ) : StoredCredential(
            storeEntry = storeEntry, status = status
        )

        class Iso(
            override val storeEntry: SubjectCredentialStore.StoreEntry.Iso,
            status: Validator.RevocationStatus
        ) : StoredCredential(
            storeEntry = storeEntry, status = status
        )
    }

    data class PresentationResponseParameters(
        val presentationSubmission: PresentationSubmission,
        val presentationResults: List<CreatePresentationResult>
    )

    /**
     * Creates [PresentationResponseParameters] (that is a list of [CreatePresentationResult] and a
     * [PresentationSubmission]) to match the [presentationDefinition].
     *
     * Fails in case the default submission is not a valid submission.
     *
     * @param fallbackFormatHolder format holder to be used in case there is no format holder in a
     *  given presentation definition and the input descriptor.
     *  This will mostly resolve to be the same as in `clientMetadata.vpFormats`.
     * @param pathAuthorizationValidator Provides the user of this library with a way to enforce
     *  authorization rules.
     */
    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder? = null,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
    ): KmmResult<PresentationResponseParameters>


    /**
     * Creates [PresentationResponseParameters] (that is a list of [CreatePresentationResult] and a
     * [PresentationSubmission]) to match the [presentationSubmissionSelection].
     *
     * Assumptions:
     *  - the presentation submission selection is a valid submission regarding the submission requirements
     *
     * @param presentationDefinitionId id of the presentation definition this submission is intended for
     * @param presentationSubmissionSelection a selection of input descriptors by `id` and
     *  corresponding credentials along with a description of the fields to be disclosed
     */
    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinitionId: String?,
        presentationSubmissionSelection: Map<String, CredentialSubmission>,
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
     */
    suspend fun matchInputDescriptorsAgainstCredentialStore(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder? = null,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
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

    sealed class CreatePresentationResult {
        /**
         * [jws] contains a valid, serialized, Verifiable Presentation that can be parsed by [Verifier.verifyPresentation]
         */
        data class Signed(val jws: String) : CreatePresentationResult()

        /**
         * [sdJwt] contains a serialized SD-JWT credential with disclosures and key binding JWT appended
         * (separated with `~` as in the specification), that can be parsed by [Verifier.verifyPresentation].
         */
        data class SdJwt(val sdJwt: String) : CreatePresentationResult()

        /**
         * [deviceResponse] contains a valid ISO 18013 [DeviceResponse] with [Document] and [DeviceSigned] structures
         */
        data class DeviceResponse(val deviceResponse: at.asitplus.wallet.lib.iso.DeviceResponse) :
            CreatePresentationResult()
    }

}

fun Map<String, Map<SubjectCredentialStore.StoreEntry, Map<ConstraintField, NodeList>>>.toDefaultSubmission() =
    mapNotNull { descriptorCredentialMatches ->
        descriptorCredentialMatches.value.entries.firstNotNullOfOrNull { credentialConstraintFieldMatches ->
            CredentialSubmission(
                credential = credentialConstraintFieldMatches.key,
                disclosedAttributes = credentialConstraintFieldMatches.value.values.mapNotNull {
                    it.firstOrNull()?.normalizedJsonPath
                },
            )
        }?.let {
            descriptorCredentialMatches.key to it
        }
    }.toMap()


/**
 * Implementations should return true, when the credential attribute may be disclosed to the verifier.
 */
typealias PathAuthorizationValidator = (credential: SubjectCredentialStore.StoreEntry, attributePath: NormalizedJsonPath) -> Boolean

open class PresentationException : Exception {
    constructor(message: String) : super(message)
    constructor(throwable: Throwable) : super(throwable)
}