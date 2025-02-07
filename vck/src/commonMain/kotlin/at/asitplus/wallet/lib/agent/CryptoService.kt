@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor

interface CryptoService {

    suspend fun sign(input: ByteArray): SignatureResult<CryptoSignature.RawByteEncodable>

    suspend fun performKeyAgreement(ephemeralKey: KeyAgreementPublicValue.ECDH): KmmResult<ByteArray>

    val keyMaterial: KeyMaterial

}

typealias VerifySignatureFun = (
    input: ByteArray,
    signature: CryptoSignature,
    algorithm: SignatureAlgorithm,
    publicKey: CryptoPublicKey,
) -> KmmResult<Verifier.Success>

object VerifySignature {
    operator fun invoke(): VerifySignatureFun = { input, signature, algorithm, publicKey ->
        algorithm.verifierFor(publicKey).transform {
            it.verify(SignatureInput(input), signature)
        }
    }
}

@Deprecated("Use VerifySignatureFun instead")
interface VerifierCryptoService {

    /**
     * List of algorithms, for which signatures can be verified in [verify].
     */
    val supportedAlgorithms: List<X509SignatureAlgorithm>

    fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: X509SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Verifier.Success>
}


open class DefaultCryptoService(
    override val keyMaterial: KeyMaterial
) : CryptoService {


    override suspend fun sign(input: ByteArray) = keyMaterial.sign(input)

    override suspend fun performKeyAgreement(ephemeralKey: KeyAgreementPublicValue.ECDH) =
       (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(ephemeralKey)

}

open class DefaultVerifierCryptoService : VerifierCryptoService {
    override val supportedAlgorithms: List<X509SignatureAlgorithm> =
        listOf(X509SignatureAlgorithm.ES256)

    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: X509SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Verifier.Success> = VerifySignature()(input, signature, algorithm.algorithm, publicKey)
}
