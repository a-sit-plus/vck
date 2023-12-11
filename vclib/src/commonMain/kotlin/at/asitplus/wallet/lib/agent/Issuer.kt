package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredential


/**
 * Summarizes operations for a Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface Issuer {

    data class FailedAttribute(val attributeName: String, val reason: Throwable)

    data class IssuedCredential(
        val vcJws: String,
        val attachments: List<Attachment>? = null,
    )

    data class IssuedCredentialResult(
        val successful: List<IssuedCredential> = listOf(),
        val failed: List<FailedAttribute> = listOf()
    ) {
        fun toStoreCredentialInput() = successful.map { Holder.StoreCredentialInput(it.vcJws, it.attachments) }
    }

    /**
     * Issues credentials for all [attributeNames] to [subjectId]
     */
    suspend fun issueCredentials(subjectId: String, attributeNames: List<String>): IssuedCredentialResult

    /**
     * Issues credential for [attributeType] to [subjectId]
     */
    suspend fun issueCredential(subjectId: String, attributeType: String): IssuedCredentialResult

    /**
     * Wraps [credential] in a single [VerifiableCredential],
     * returns a JWS representation of that VC.
     */
    suspend fun issueCredential(credential: IssuerCredentialDataProvider.CredentialToBeIssued): IssuedCredentialResult

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
