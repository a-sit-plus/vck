package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentation
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

    sealed class StoredCredential {
        data class Vc(
            val vcSerialized: String,
            val vc: VerifiableCredentialJws,
            val status: Validator.RevocationStatus
        ) : StoredCredential()

        data class SdJwt(
            val vcSerialized: String,
            val sdJwt: VerifiableCredentialSdJwt,
            val status: Validator.RevocationStatus
        ) : StoredCredential()

        data class Iso(
            val issuerSigned: IssuerSigned
        ) : StoredCredential()
    }

    data class HolderResponseParameters(
        val presentationSubmission: PresentationSubmission,
        val verifiablePresentations: List<CreatePresentationResult>
    )

    /**
     * Creates an array of [VerifiablePresentation] and a [PresentationSubmission] to match
     * the [presentationDefinition]. Optionally filters by [requestedClaims] (e.g. in ISO case).
     *
     * May return null if no presentation can be made (i.e. no matching credentials available).
     */
    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
        // TODO: add authorization semantics to detect unauthorized requests
        // - eg. a service provider asking for an attribute he should not be allowed to see
    ): HolderResponseParameters?

    /**
     * Creates a [VerifiablePresentation] serialized as a JWT for all the credentials we have stored,
     * that match the [credentialSchemes] (if specified). Optionally filters by [requestedClaims] (e.g. in ISO case).
     *
     * May return null if no valid credentials (i.e. non-revoked, matching attribute name) are available.
     */
    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        credentialSchemes: Collection<ConstantIndex.CredentialScheme>? = null,
        requestedClaims: Collection<String>? = null,
    ): CreatePresentationResult?

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    // TODO dont make this public
    suspend fun createPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): CreatePresentationResult?

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
        data class Document(val document: at.asitplus.wallet.lib.iso.Document) : CreatePresentationResult()
    }

}
