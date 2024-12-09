package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusProvider
import at.asitplus.wallet.lib.iso.IssuerSigned
import kotlinx.datetime.Instant


/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
@OptIn(ExperimentalUnsignedTypes::class)
interface Issuer : ReferencedTokenIssuer<CredentialToBeIssued, KmmResult<Issuer.IssuedCredential>>, StatusIssuer<String, ByteArray>, StatusProvider<Any> {

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
     * Wraps the credential-to-be-issued in [credential] into a single instance of [IssuedCredential],
     * according to the representation, i.e. it essentially signs the credential with the issuer key.
     */
    suspend fun issueCredential(credential: CredentialToBeIssued): KmmResult<IssuedCredential>
    override suspend fun issueToken(tokenRequest: CredentialToBeIssued) = issueCredential(credential = tokenRequest)

    /**
     * Returns a status list as defined in [TokenListStatus](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html)
     */
    fun buildStatusList(timePeriod: Int? = null): StatusList?

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