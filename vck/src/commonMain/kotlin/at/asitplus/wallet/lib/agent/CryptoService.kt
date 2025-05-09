@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor

interface CryptoService {

    suspend fun sign(input: ByteArray): SignatureResult<CryptoSignature.RawByteEncodable>

    fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<AuthenticatedCiphertext>

    suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<ByteArray>

    fun generateEphemeralKeyPair(ecCurve: ECCurve): EphemeralKeyHolder

    suspend fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm,
    ): KmmResult<ByteArray>

    suspend fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray>

    fun messageDigest(input: ByteArray, digest: Digest): ByteArray

    fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray>

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


data class AuthenticatedCiphertext(val ciphertext: ByteArray, val authtag: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthenticatedCiphertext

        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authtag.contentEquals(other.authtag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + authtag.contentHashCode()
        return result
    }
}

expect open class PlatformCryptoShim() {


    open fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<AuthenticatedCiphertext>

    open suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<ByteArray>

    open fun hmac(
        key: ByteArray,
        algorithm: JweEncryption,
        input: ByteArray,
    ): KmmResult<ByteArray>
}

open class DefaultCryptoService(
    override val keyMaterial: KeyMaterial,
) : CryptoService {

    private val platformCryptoShim by lazy { PlatformCryptoShim() }

    override suspend fun sign(input: ByteArray) = keyMaterial.sign(input)

    override fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<AuthenticatedCiphertext> =
        platformCryptoShim.encrypt(key, iv, aad, input, algorithm)

    override suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption,
    ): KmmResult<ByteArray> =
        platformCryptoShim.decrypt(key, iv, aad, input, authTag, algorithm)

    override fun generateEphemeralKeyPair(ecCurve: ECCurve) = DefaultEphemeralKeyHolder(ecCurve)


    override suspend fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm,
    ): KmmResult<ByteArray> = catching {
        //this is temporary until we refactor the JWS service and both key agreement functions get merged
        @OptIn(SecretExposure::class)
        (recipientKey.toCryptoPublicKey()
            .getOrThrow() as CryptoPublicKey.EC).keyAgreement(
            ephemeralKey.key.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>
        ).getOrThrow()
    }

    override suspend fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm,
    ): KmmResult<ByteArray> = catching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
        //this is temporary until we refactor the JWS service and both key agreement functions get merged
        (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(publicKey).getOrThrow()
    }

    override fun hmac(key: ByteArray, algorithm: JweEncryption, input: ByteArray): KmmResult<ByteArray> =
        platformCryptoShim.hmac(key, algorithm, input)

    override fun messageDigest(
        input: ByteArray,
        digest: Digest,
    ) = digest.digest(sequenceOf(input))
}

@Deprecated("Use VerifySignatureFun instead")
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
