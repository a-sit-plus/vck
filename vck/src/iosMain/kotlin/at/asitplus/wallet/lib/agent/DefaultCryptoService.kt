@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.DefaultCryptoService.Companion.signInt
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.cinterop.*
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.ExperimentalNativeApi
import platform.CoreFoundation.CFDictionaryAddValue as CFDictionaryAddValue1


/**
 * Default implementation of a crypto service for iOS.
 *
 * The primary goal is to provide a minimal implementation so that unit tests in the `commonTest` module run successfully.
 *
 * Beware: It does **not** implement encryption, decryption, key agreement and message digest correctly.
 */
@Suppress("UNCHECKED_CAST")
actual class DefaultCryptoService : CryptoService {

    actual override val keyPairAdapter: KeyPairAdapter
    private val iosKeyPairAdapter: IosKeyPairAdapter

    actual constructor(keyPairAdapter: KeyPairAdapter) {
        assert(keyPairAdapter is IosKeyPairAdapter)
        keyPairAdapter as IosKeyPairAdapter
        this.keyPairAdapter = keyPairAdapter
        this.iosKeyPairAdapter = keyPairAdapter
    }

    actual override suspend fun doSign(input: ByteArray): KmmResult<CryptoSignature> {
        return KmmResult.success(CryptoSignature.decodeFromDer(signInt(input, iosKeyPairAdapter.secPrivateKey)))
    }

    actual override fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> {
        return KmmResult.success(
            AuthenticatedCiphertext(
                input.reversedArray(),
                "authtag-${key.encodeToString(Base64Strict)}".encodeToByteArray()
            )
        )
    }

    actual override suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> {
        return if (authTag.contentEquals("authtag-${key.encodeToString(Base64Strict)}".encodeToByteArray()))
            KmmResult.success(input.reversedArray())
        else
            KmmResult.failure(IllegalArgumentException())
    }

    actual override fun generateEphemeralKeyPair(ecCurve: ECCurve): KmmResult<EphemeralKeyHolder> {
        val query = CFDictionaryCreateMutable(null, 2, null, null).apply {
            CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
            CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
        }
        val privateKey = SecKeyCreateRandomKey(query, null)
            ?: return KmmResult.failure(Exception("Cannot create in-memory private key"))
        val publicKey = SecKeyCopyPublicKey(privateKey)
            ?: return KmmResult.failure(Exception("Cannot create public key"))
        return KmmResult.success(DefaultEphemeralKeyHolder(ecCurve, publicKey, privateKey))
    }

    actual override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.identifier}".encodeToByteArray())
    }

    actual override fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.identifier}".encodeToByteArray())
    }

    actual override fun messageDigest(
        input: ByteArray,
        digest: at.asitplus.signum.indispensable.Digest
    ): KmmResult<ByteArray> {
        return KmmResult.success(input)
    }

    companion object {
        fun signInt(input: ByteArray, privateKeyRef: SecKeyRef): ByteArray {
            memScoped {
                val inputData = CFBridgingRetain(toData(input)) as CFDataRef
                val signature =
                    SecKeyCreateSignature(privateKeyRef, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, inputData, null)
                val data = CFBridgingRelease(signature) as NSData
                return data.toByteArray()
            }
        }
    }

}

actual fun RandomKeyPairAdapter(extensions: List<X509CertificateExtension>): KeyPairAdapter {
    val query = CFDictionaryCreateMutable(null, 2, null, null).apply {
        CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
        CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
    }
    val secPrivateKey = SecKeyCreateRandomKey(query, null)!!
    val secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!!
    val publicKeyData = SecKeyCopyExternalRepresentation(secPublicKey, null)
    val data = CFBridgingRelease(publicKeyData) as NSData
    val publicKey = CryptoPublicKey.EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, data.toByteArray())
    val signingAlgorithm = X509SignatureAlgorithm.ES256
    val certificate = X509Certificate.generateSelfSignedCertificate(publicKey, signingAlgorithm, extensions) {
        val intSign = signInt(it, secPrivateKey)
        KmmResult.success(CryptoSignature.decodeFromDer(intSign))
    }
    return IosKeyPairAdapter(secPrivateKey, secPublicKey, signingAlgorithm, certificate)
}

class IosKeyPairAdapter(
    val secPrivateKey: SecKeyRef,
    val secPublicKey: SecKeyRef,
    override val signingAlgorithm: X509SignatureAlgorithm,
    override val certificate: X509Certificate?
) : KeyPairAdapter {
    private val publicKeyData = SecKeyCopyExternalRepresentation(secPublicKey, null)
    private val data = CFBridgingRelease(publicKeyData) as NSData
    override val publicKey: CryptoPublicKey =
        CryptoPublicKey.EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, data.toByteArray())
    override val identifier: String = publicKey.didEncoded
    override val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey()
    override val coseKey: CoseKey
        get() = publicKey.toCoseKey(signingAlgorithm.toCoseAlgorithm().getOrThrow()).getOrThrow()

}

@Suppress("UNCHECKED_CAST")
actual class DefaultVerifierCryptoService : VerifierCryptoService {

    actual override val supportedAlgorithms: List<X509SignatureAlgorithm> =
        X509SignatureAlgorithm.entries.filter { it.isEc }

    actual override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: X509SignatureAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Boolean> {
        // TODO RSA
        if (publicKey !is CryptoPublicKey.EC) {
            return KmmResult.failure(IllegalArgumentException("Public key is not an EC key"))
        }
        memScoped {
            val ansix962 = publicKey.iosEncoded
            val keyData = CFBridgingRetain(toData(ansix962)) as CFDataRef
            val attributes = CFDictionaryCreateMutable(null, 3, null, null).apply {
                CFDictionaryAddValue1(this, kSecAttrKeyClass, kSecAttrKeyClassPublic)
                CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
                CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
            }
            val secKey = SecKeyCreateWithData(keyData, attributes, null)
                ?: return KmmResult.failure(IllegalArgumentException())
            val inputData = CFBridgingRetain(toData(input)) as CFDataRef
            val signatureData = CFBridgingRetain(toData(signature.encodeToDer())) as CFDataRef
            val verified = SecKeyVerifySignature(
                key = secKey,
                algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                signedData = inputData,
                signature = signatureData,
                error = null
            )
            return KmmResult.success(verified)
        }
    }

}

data class DefaultEphemeralKeyHolder(val crv: ECCurve, val publicKey: SecKeyRef, val privateKey: SecKeyRef? = null) :
    EphemeralKeyHolder {

    override val publicJsonWebKey = CryptoPublicKey.EC.fromAnsiX963Bytes(
        crv,
        (CFBridgingRelease(
            SecKeyCopyExternalRepresentation(
                publicKey,
                null
            )
        ) as NSData).toByteArray()
    ).toJsonWebKey()
}

inline fun MemScope.toData(array: ByteArray): NSData =
    NSData.create(
        bytes = allocArrayOf(array),
        length = array.size.toULong()
    )

// from https://github.com/mirego/trikot.foundation/pull/41/files
public fun NSData.toByteArray(): ByteArray {
    return this.bytes?.let {
        val dataPointer: CPointer<ByteVar> = it.reinterpret()
        ByteArray(this.length.toInt()) { index -> dataPointer[index] }
    } ?: ByteArray(0)
}
