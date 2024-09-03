@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.os.PlatformSigningProviderSigner
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.verifierFor

interface CryptoService {

    suspend fun sign(input: ByteArray): KmmResult<CryptoSignature.RawByteEncodable> =
        when (val sig = doSign(input)) {
            //TODO: this needs to be nicer, once sigresult supports generics

            is SignatureResult.Error -> KmmResult.failure(sig.exception)
            is SignatureResult.Failure -> KmmResult.failure(sig.problem)
            is SignatureResult.Success -> {
                when (val sigValue = sig.signature) {
                    is CryptoSignature.RawByteEncodable -> sigValue
                    is CryptoSignature.NotRawByteEncodable -> when (sigValue) {
                        is CryptoSignature.EC.IndefiniteLength -> sigValue.withCurve((keyPairAdapter.publicKey as CryptoPublicKey.EC).curve)
                    }
                }.let { KmmResult(it) }
            }
        }


    suspend fun doSign(
        input: ByteArray,
        promptText: String? = null,
        cancelText: String? = null
    ): SignatureResult

    fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext>

    suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray>

    fun generateEphemeralKeyPair(ecCurve: ECCurve): EphemeralKeyHolder

    fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray>

    fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray>

    fun messageDigest(input: ByteArray, digest: Digest): ByteArray

    val keyPairAdapter: KeyPairAdapter

}

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
    ): KmmResult<Unit>

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

expect class PlatformCryptoShim constructor(keyPairAdapter: KeyPairAdapter) {

    val keyPairAdapter: KeyPairAdapter

    fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext>

    suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray>

    fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray>

    fun performKeyAgreement(
        ephemeralKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray>
}

open class DefaultCryptoService(
    override val keyPairAdapter: KeyPairAdapter
) : CryptoService {

    private val platformCryptoShim = PlatformCryptoShim(keyPairAdapter)

    override suspend fun doSign(
        input: ByteArray,
        promptText: String?,
        cancelText: String?
    ): SignatureResult =
        when (val signer = keyPairAdapter.signer) {
            is PlatformSigningProviderSigner<*> -> signer.sign(input) {
                unlockPrompt {
                    promptText?.let { message = it }
                    cancelText?.let { this.cancelText = cancelText }
                }
            }
            else -> keyPairAdapter.signer.sign(input)
        }


    override fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> =
        platformCryptoShim.encrypt(key, iv, aad, input, algorithm)

    override suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> = platformCryptoShim.decrypt(key, iv, aad, input, authTag, algorithm)

    override fun generateEphemeralKeyPair(ecCurve: ECCurve) = DefaultEphemeralKeyHolder(ecCurve)

    override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ) = platformCryptoShim.performKeyAgreement(ephemeralKey, recipientKey, algorithm)

    override fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm) =
        platformCryptoShim.performKeyAgreement(ephemeralKey, algorithm)


    override fun messageDigest(
        input: ByteArray,
        digest: Digest
    ) = digest.digest(input)
}

open class DefaultVerifierCryptoService : VerifierCryptoService {
    override val supportedAlgorithms: List<X509SignatureAlgorithm> =
        listOf(X509SignatureAlgorithm.ES256)

    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: X509SignatureAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Unit> = algorithm.algorithm.verifierFor(publicKey).map {
        it.verify(SignatureInput(input), signature)
    }
}
