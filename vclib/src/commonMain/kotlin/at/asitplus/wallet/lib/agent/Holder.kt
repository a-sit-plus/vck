package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.iso.IssuerSigned

/**
 * Summarizes operations for a Holder in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can store Verifiable Credentials, and create a Verifiable Presentation out of the stored credentials
 */
interface Holder {

    /**
     * The identifier for this agent, typically the `keyId` from the cryptographic key,
     * e.g. `did:key:mAB...` or `urn:ietf:params:oauth:jwk-thumbprint:sha256:...`
     */
    val identifier: String

    val defaultPathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean

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
            val attachments: List<Issuer.Attachment>? = null
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
     * Stores all verifiable credentials from [credentialList] that parse and validate,
     * and returns them for future reference.
     *
     * Note: Revocation credentials should not be stored, but set with [setRevocationList].
     */
    suspend fun storeCredentials(credentialList: List<StoreCredentialInput>): StoredCredentialsResult

    data class StoredCredentialsResult(
        val acceptedVcJwt: List<VerifiableCredentialJws> = listOf(),
        val acceptedSdJwt: List<VerifiableCredentialSdJwt> = listOf(),
        val acceptedIso: List<IssuerSigned> = listOf(),
        val rejected: List<String> = listOf(),
        val notVerified: List<String> = listOf(),
        val attachments: List<StoredAttachmentResult> = listOf(),
    )

    data class StoredAttachmentResult(val name: String, val data: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as StoredAttachmentResult

            if (name != other.name) return false
            if (!data.contentEquals(other.data)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

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
     * Creates an array of [VerifiablePresentation] and a [PresentationSubmission] to match
     * the [presentationDefinition].
     *
     * @param fallbackFormatHolder: format holder to be used in case there is no format holder in a
     *  given presentation definition and the input descriptor.
     *  This will mostly resolve to be the some clientMetadata.vpFormats
     * @param pathAuthorizationValidator: Provides the user of this library with a way to enforce
     *  authorization rules.
     */
    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder? = null,
        pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean = defaultPathAuthorizationValidator,
    ): KmmResult<PresentationResponseParameters>

    /**
     * Creates a mapping from the input descriptors of the presentation definition to matching
     * credentials and the fields that would need to be disclosed.
     *
     * @param fallbackFormatHolder: format holder to be used in case there is no format holder in a
     *  given presentation definition and the input descriptor.
     *  This will mostly resolve to be the some clientMetadata.vpFormats
     * @param pathAuthorizationValidator: Provides the user of this library with a way to enforce
     *  authorization rules.
     */
    suspend fun matchInputDescriptorsAgainstCredentialStore(
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<InputDescriptor, HolderAgent.CandidateInputMatchContainer?>>

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
         * [document] contains a valid ISO 18013 [Document] with [IssuerSigned] and [DeviceSigned] structures
         */
        data class Document(val document: at.asitplus.wallet.lib.iso.Document) :
            CreatePresentationResult()
    }

}
