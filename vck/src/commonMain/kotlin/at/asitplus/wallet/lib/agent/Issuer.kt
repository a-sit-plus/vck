package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenIssuer
import at.asitplus.wallet.lib.iso.IssuerSigned


/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface Issuer : ReferencedTokenIssuer<CredentialToBeIssued, KmmResult<Issuer.IssuedCredential>> {

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

    override suspend fun issueToken(tokenRequest: CredentialToBeIssued) =
        issueCredential(credential = tokenRequest)

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

}

fun Issuer.IssuedCredential.toStoreCredentialInput() = when (this) {
    is Issuer.IssuedCredential.Iso -> Holder.StoreCredentialInput.Iso(issuerSigned, scheme)
    is Issuer.IssuedCredential.VcSdJwt -> Holder.StoreCredentialInput.SdJwt(vcSdJwt, scheme)
    is Issuer.IssuedCredential.VcJwt -> Holder.StoreCredentialInput.Vc(vcJws, scheme)
}