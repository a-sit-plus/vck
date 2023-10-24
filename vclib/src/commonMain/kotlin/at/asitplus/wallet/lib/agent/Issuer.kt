package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.iso.IssuerSigned
import kotlinx.datetime.Instant


/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface Issuer {

    data class FailedAttribute(val attributeType: String, val reason: Throwable)

    /**
     * A credential issued by an [Issuer], in a specific format
     */
    sealed class IssuedCredential {
        /**
         * Issued credential in W3C Verifiable Credentials JWT representation
         */
        data class VcJwt(
            val vcJws: String,
            val scheme: ConstantIndex.CredentialScheme,
            val attachments: List<Attachment>? = null,
        ) : IssuedCredential()

        /**
         * Issued credential in SD-JWT representation
         */
        data class VcSdJwt(
            val vcSdJwt: String,
            val scheme: ConstantIndex.CredentialScheme,
        ) : IssuedCredential()

        /**
         * Issued credential in ISO 18013-5 format
         */
        data class Iso(
            val issuerSigned: IssuerSigned,
            val scheme: ConstantIndex.CredentialScheme,
        ) : IssuedCredential()
    }

    data class IssuedCredentialResult(
        val successful: List<IssuedCredential> = listOf(),
        val failed: List<FailedAttribute> = listOf()
    ) {
        fun toStoreCredentialInput() = successful.map {
            when (it) {
                is IssuedCredential.Iso -> Holder.StoreCredentialInput.Iso(it.issuerSigned, it.scheme)
                is IssuedCredential.VcSdJwt -> Holder.StoreCredentialInput.SdJwt(it.vcSdJwt, it.scheme)
                is IssuedCredential.VcJwt -> Holder.StoreCredentialInput.Vc(it.vcJws, it.scheme, it.attachments)
            }
        }
    }

    /**
     * The identifier for this agent, typically the `keyId` from the cryptographic key,
     * e.g. `did:key:mAB...` or `urn:ietf:params:oauth:jwk-thumbprint:sha256:...`
     */
    val identifier: String

    /**
     * Issues credentials for some [attributeTypes] (i.e. some of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]) to the subject specified with its public
     * key in [subjectPublicKey] in the format specified by [representation].
     */
    suspend fun issueCredential(
        subjectPublicKey: CryptoPublicKey,
        attributeTypes: Collection<String>,
        representation: ConstantIndex.CredentialRepresentation,
    ): IssuedCredentialResult

    /**
     * Wraps the revocation information into a VC,
     * returns a JWS representation of that.
     * @param timePeriod time Period to issue a revocation list for
     */
    suspend fun issueRevocationListCredential(timePeriod: Int? = null): String?

    /**
     * Returns a Base64-encoded, zlib-compressed bitstring of revoked credentials, where
     * the entry at "revocationListIndex" (of the credential) is true iff it is revoked
     */
    fun buildRevocationList(timePeriod: Int? = null): String?

    /**
     * Revokes all verifiable credentials from [credentialsToRevoke] list that parse and validate.
     * It returns true if all revocations was successful.
     */
    fun revokeCredentials(credentialsToRevoke: List<String>): Boolean

    /**
     * Revokes all verifiable credentials with ids and issuance date from [credentialIdsToRevoke]
     * It returns true if all revocations was successful.
     */
    fun revokeCredentialsWithId(credentialIdsToRevoke: Map<String, Instant>): Boolean

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
