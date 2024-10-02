package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSigned
import kotlinx.datetime.Instant


/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface Issuer {

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


    /**
     * The public key for this agent, i.e. the public part of the key that signs issued credentials.
     */
    val keyMaterial: KeyMaterial

    /**
     * The cryptographic algorithms supported by this issuer, i.e. the ones from its cryptographic service,
     * used to sign credentials.
     */
    val cryptoAlgorithms: Set<SignatureAlgorithm>

    /**
     * Issues credentials for some [credentialScheme] to the subject specified with its public
     * key in [subjectPublicKey] in the format specified by [representation].
     * Callers may optionally define some attribute names from [ConstantIndex.CredentialScheme.claimNames] in
     * [claimNames] to request only some claims (if supported by the representation).
     *
     * @param dataProviderOverride Set this parameter to override the default [IssuerCredentialDataProvider] for this
     *                             issuing process
     */
    suspend fun issueCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>? = null,
        dataProviderOverride: IssuerCredentialDataProvider? = null,
    ): KmmResult<IssuedCredential>

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

}

fun Issuer.IssuedCredential.toStoreCredentialInput() = when (this) {
    is Issuer.IssuedCredential.Iso -> Holder.StoreCredentialInput.Iso(issuerSigned, scheme)
    is Issuer.IssuedCredential.VcSdJwt -> Holder.StoreCredentialInput.SdJwt(vcSdJwt, scheme)
    is Issuer.IssuedCredential.VcJwt -> Holder.StoreCredentialInput.Vc(vcJws, scheme)
}
