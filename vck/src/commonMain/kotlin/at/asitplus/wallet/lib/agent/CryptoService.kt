@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SealedBox
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt

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

    fun decrypt(
        key: SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>,
        iv: ByteArray,
        aad: ByteArray,
        encryptedData: ByteArray,
        authTag: ByteArray
    ): KmmResult<ByteArray>

    fun encrypt(
        key: SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>,
        plaintext: ByteArray,
        aad: ByteArray
    ): KmmResult<SealedBox<AuthCapability.Authenticated<*>, NonceTrait.Required, *>>
}

@Deprecated("Use VerifySignatureFun instead")
interface VerifierCryptoService {

    /**
     * List of algorithms, for which signatures can be verified in [verify].
     */
    val supportedAlgorithms: List<SignatureAlgorithm>

    fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Verifier.Success>
}


open class DefaultCryptoService(
    override val keyMaterial: KeyMaterial
) : CryptoService {


    override fun decrypt(
        key: SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>,
        iv: ByteArray,
        aad: ByteArray,
        encryptedData: ByteArray,
        authTag: ByteArray
    ) = catching { key.decrypt(iv, encryptedData, authTag, aad).getOrThrow() }

    override fun encrypt(
        key: SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>,
        plaintext: ByteArray,
        aad: ByteArray
    ) = key.encrypt(plaintext, authenticatedData = aad)


    override suspend fun sign(input: ByteArray) = keyMaterial.sign(input)

    override suspend fun performKeyAgreement(ephemeralKey: KeyAgreementPublicValue.ECDH) =
        (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(ephemeralKey)

}

open class DefaultVerifierCryptoService : VerifierCryptoService {
    override val supportedAlgorithms: List<SignatureAlgorithm> =
        listOf(SignatureAlgorithm.ECDSAwithSHA256)

    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Verifier.Success> = algorithm.verifierFor(publicKey).transform {
        it.verify(SignatureInput(input), signature)
    }
}
