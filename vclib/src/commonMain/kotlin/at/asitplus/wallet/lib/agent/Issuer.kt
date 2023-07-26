package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.iso.IssuerSigned


/**
 * Summarizes operations for a Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface Issuer {

    data class FailedAttribute(val attributeName: String, val reason: Throwable)

    sealed class IssuedCredential {
        data class Vc(val vcJws: String, val attachments: List<Attachment>? = null) : IssuedCredential()
        data class Iso(val issuerSigned: IssuerSigned) : IssuedCredential()
    }

    data class IssuedCredentialResult(
        val successful: List<IssuedCredential> = listOf(),
        val failed: List<FailedAttribute> = listOf()
    ) {
        fun toStoreCredentialInput() = successful.filterIsInstance<IssuedCredential.Vc>()
            .map { Holder.StoreCredentialInput.Vc(it.vcJws, it.attachments) }
    }

    /**
     * The identifier for this agent, typically the `keyId` from the cryptographic key,
     * e.g. `did:key:mAB...` or `urn:ietf:params:oauth:jwk-thumbprint:sha256:...`
     */
    val identifier: String

    /**
     * Issues credentials for some [attributeTypes] (i.e. some of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]) to the subject specified with [subjectId]
     * (which should be a URL of the cryptographic key of the holder) or with [subjectPublicKey].
     */
    suspend fun issueCredentialWithTypes(
        subjectId: String,
        subjectPublicKey: CoseKey? = null,
        attributeTypes: Collection<String>
    ): IssuedCredentialResult

    /**
     * Wraps [credential] in a single [VerifiableCredential],
     * returns a JWS representation of that VC.
     */
    suspend fun issueCredential(credential: CredentialToBeIssued): IssuedCredentialResult

    /**
     * Wraps the revocation information into a VC,
     * returns a JWS representation of that.
     * @param timePeriod time Period to issue a revocation list for
     */
    suspend fun issueRevocationListCredential(timePeriod: Int): String?

    /**
     * Returns a Base64-encoded, zlib-compressed bitstring of revoked credentials, where
     * the entry at "revocationListIndex" (of the credential) is true iff it is revoked
     */
    fun buildRevocationList(timePeriod: Int): String?

    /**
     * Revokes all verifiable credentials from [credentialsToRevoke] list that parse and validate.
     * It returns true if all revocations was successful. Note: only the issuer can revoke.
     */
    fun revokeCredentials(credentialsToRevoke: List<String>): Boolean

    fun compileCurrentRevocationLists(): List<String>

    data class Attachment(
        val name: String,
        val mediaType: String,
        val data: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Attachment

            if (name != other.name) return false
            if (mediaType != other.mediaType) return false
            if (!data.contentEquals(other.data)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + mediaType.hashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }

}
