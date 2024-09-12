package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.jws.*

interface CryptoService {

    suspend fun sign(input: ByteArray): KmmResult<ByteArray>

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

    fun generateEphemeralKeyPair(ecCurve: EcCurve): KmmResult<EphemeralKeyHolder>

    fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray>

    fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray>

    fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray>

    val keyId: String

    val jwsAlgorithm: JwsAlgorithm

    fun toJsonWebKey(): JsonWebKey

}

interface VerifierCryptoService {

    fun verify(
        input: ByteArray,
        signature: ByteArray,
        algorithm: JwsAlgorithm,
        publicKey: JsonWebKey
    ): KmmResult<Boolean>

    fun extractPublicKeyFromX509Cert(it: ByteArray): JsonWebKey?

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

interface EphemeralKeyHolder {
    fun toPublicJsonWebKey(): JsonWebKey
}

expect class DefaultCryptoService() : CryptoService {
    override suspend fun sign(input: ByteArray): KmmResult<ByteArray>
    override fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext>

    override suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray>

    override fun generateEphemeralKeyPair(ecCurve: EcCurve): KmmResult<EphemeralKeyHolder>

    override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray>

    override fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray>

    override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray>

    override val keyId: String

    override val jwsAlgorithm: JwsAlgorithm

    override fun toJsonWebKey(): JsonWebKey
}

expect class DefaultVerifierCryptoService() : VerifierCryptoService {
    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        algorithm: JwsAlgorithm,
        publicKey: JsonWebKey
    ): KmmResult<Boolean>

    override fun extractPublicKeyFromX509Cert(it: ByteArray): JsonWebKey?
}
