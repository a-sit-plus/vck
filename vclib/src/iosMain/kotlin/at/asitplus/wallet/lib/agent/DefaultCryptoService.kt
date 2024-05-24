@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.X509CertificateExtension
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.reinterpret
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSNumber
import platform.Foundation.create
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyRef
import platform.Security.SecKeyVerifySignature
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
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

    private val secPrivateKey: SecKeyRef
    private val secPublicKey: SecKeyRef
    override val algorithm = CryptoAlgorithm.ES256
    override val publicKey: CryptoPublicKey
    override val certificate: X509Certificate

    override val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey()

    override val coseKey: CoseKey
        get() = publicKey.toCoseKey(CoseAlgorithm.ES256).getOrNull()!!

    actual constructor() : this(listOf())

    constructor(certificateExtensions: List<X509CertificateExtension>) {
        val query = CFDictionaryCreateMutable(null, 2, null, null).apply {
            CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
            CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
        }
        secPrivateKey = SecKeyCreateRandomKey(query, null)!!
        secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!!
        val publicKeyData = SecKeyCopyExternalRepresentation(secPublicKey, null)
        val data = CFBridgingRelease(publicKeyData) as NSData
        publicKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(data.toByteArray())
        this.certificate = X509Certificate.generateSelfSignedCertificate(this, extensions = certificateExtensions)
    }

    private fun signInt(input: ByteArray): ByteArray {
        memScoped {
            val inputData = CFBridgingRetain(toData(input)) as CFDataRef
            val signature =
                SecKeyCreateSignature(secPrivateKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, inputData, null)
            val data = CFBridgingRelease(signature) as NSData
            return data.toByteArray()
        }
    }

    override suspend fun sign(input: ByteArray): KmmResult<CryptoSignature> {
        return KmmResult.success(CryptoSignature.decodeFromDer(signInt(input)))
    }

    override fun encrypt(
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

    override suspend fun decrypt(
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

    override fun generateEphemeralKeyPair(ecCurve: EcCurve): KmmResult<EphemeralKeyHolder> {
        val query = CFDictionaryCreateMutable(null, 2, null, null).apply {
            CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
            CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
        }
        val privateKey = SecKeyCreateRandomKey(query, null)
            ?: return KmmResult.failure(Exception("Cannot create in-memory private key"))
        val publicKey = SecKeyCopyPublicKey(privateKey)
            ?: return KmmResult.failure(Exception("Cannot create public key"))
        return KmmResult.success(DefaultEphemeralKeyHolder(publicKey, privateKey))
    }

    override fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        algorithm: JweAlgorithm
    ): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.text}".encodeToByteArray())
    }

    override fun performKeyAgreement(ephemeralKey: JsonWebKey, algorithm: JweAlgorithm): KmmResult<ByteArray> {
        return KmmResult.success("sharedSecret-${algorithm.text}".encodeToByteArray())
    }

    override fun messageDigest(input: ByteArray, digest: at.asitplus.crypto.datatypes.Digest): KmmResult<ByteArray> {
        return KmmResult.success(input)
    }

    actual companion object {
        actual fun withSelfSignedCert(extensions: List<X509CertificateExtension>): CryptoService =
            DefaultCryptoService(certificateExtensions = extensions)
    }
}

@Suppress("UNCHECKED_CAST")
actual class DefaultVerifierCryptoService : VerifierCryptoService {

    override val supportedAlgorithms: List<CryptoAlgorithm> = CryptoAlgorithm.entries.filter { it.isEc }

    override fun verify(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: CryptoAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Boolean> {
        // TODO RSA
        if (publicKey !is CryptoPublicKey.Ec) {
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

data class DefaultEphemeralKeyHolder(val publicKey: SecKeyRef, val privateKey: SecKeyRef? = null) : EphemeralKeyHolder {

    override val publicJsonWebKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(
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
