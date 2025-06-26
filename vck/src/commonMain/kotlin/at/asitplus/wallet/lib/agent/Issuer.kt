package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenIssuer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.SdJwtSigned


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
        // TODO add the userInfo
        abstract val scheme: ConstantIndex.CredentialScheme

        /**
         * Issued credential in W3C Verifiable Credentials JWT representation
         */
        data class VcJwt(
            val vc: VerifiableCredential,
            val signedVcJws: JwsSigned<VerifiableCredentialJws>,
            @Deprecated("Use signedVcJws instead", ReplaceWith("signedVcJws"))
            val vcJws: String,
            override val scheme: ConstantIndex.CredentialScheme,
        ) : IssuedCredential()

        /**
         * Issued credential in SD-JWT representation
         */
        data class VcSdJwt(
            val sdJwtVc: VerifiableCredentialSdJwt,
            val signedSdJwtVc: SdJwtSigned,
            @Deprecated("Use signedSdJwtVc instead", ReplaceWith("signedSdJwtVc"))
            val vcSdJwt: String,
            override val scheme: ConstantIndex.CredentialScheme,
        ) : IssuedCredential()

        /**
         * Issued credential in ISO 18013-5 format
         */
        data class Iso(
            val issuerSigned: IssuerSigned,
            override val scheme: ConstantIndex.CredentialScheme,
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
    is Issuer.IssuedCredential.VcSdJwt -> Holder.StoreCredentialInput.SdJwt(signedSdJwtVc, signedSdJwtVc.serialize(), scheme)
    is Issuer.IssuedCredential.VcJwt -> Holder.StoreCredentialInput.Vc(signedVcJws, signedVcJws.serialize(), scheme)
}