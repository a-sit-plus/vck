@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.data.Base64Strict
import at.asitplus.wallet.lib.jws.EcCurve
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JweAlgorithm
import at.asitplus.wallet.lib.jws.JweEncryption
import at.asitplus.wallet.lib.jws.JwkType
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsExtensions.convertToAsn1Signature
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
import platform.Security.SecCertificateCopyKey
import platform.Security.SecCertificateCreateWithData
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

    override val jwsAlgorithm = JwsAlgorithm.ES256
    override val coseAlgorithm = CoseAlgorithm.ES256
    private val privateKey: SecKeyRef
    private val publicKey: SecKeyRef
    private val cryptoPublicKey: CryptoPublicKey
    final override val certificate: ByteArray

    actual constructor() {
        val query = CFDictionaryCreateMutable(null, 2, null, null).apply {
            CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
            CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
        }
        privateKey = SecKeyCreateRandomKey(query, null)!!
        publicKey = SecKeyCopyPublicKey(privateKey)!!
        val publicKeyData = SecKeyCopyExternalRepresentation(publicKey, null)
        val data = CFBridgingRelease(publicKeyData) as NSData
        this.cryptoPublicKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(EcCurve.SECP_256_R_1, data.toByteArray())!!
        this.certificate = byteArrayOf() // TODO How to create a self-signed certificate in Kotlin/iOS?
    }

    override suspend fun sign(input: ByteArray): KmmResult<ByteArray> {
        memScoped {
            val inputData = CFBridgingRetain(toData(input)) as CFDataRef
            val signature =
                SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, inputData, null)
            val data = CFBridgingRelease(signature) as NSData
            return KmmResult.success(data.toByteArray())
        }
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

    override fun messageDigest(input: ByteArray, digest: Digest): KmmResult<ByteArray> {
        return KmmResult.success(input)
    }

    override fun toPublicKey() = cryptoPublicKey
}

@Suppress("UNCHECKED_CAST")
actual class DefaultVerifierCryptoService : VerifierCryptoService {

    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        algorithm: JwsAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Boolean> {
        if (publicKey !is CryptoPublicKey.Ec) {
            return KmmResult.failure(IllegalArgumentException("Public key is not an EC key"))
        }
        memScoped {
            val ansix962 = publicKey.toAnsiX963ByteArray().getOrElse {
                return KmmResult.failure(it)
            }
            val keyData = CFBridgingRetain(toData(ansix962)) as CFDataRef
            val attributes = CFDictionaryCreateMutable(null, 3, null, null).apply {
                CFDictionaryAddValue1(this, kSecAttrKeyClass, kSecAttrKeyClassPublic)
                CFDictionaryAddValue1(this, kSecAttrKeyType, kSecAttrKeyTypeEC)
                CFDictionaryAddValue1(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(256)))
            }
            val secKey = SecKeyCreateWithData(keyData, attributes, null)
                ?: return KmmResult.failure(IllegalArgumentException())
            val inputData = CFBridgingRetain(toData(input)) as CFDataRef
            val signatureData = CFBridgingRetain(toData(signature.convertToAsn1Signature(32))) as CFDataRef
            val verified = SecKeyVerifySignature(
                secKey,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                inputData,
                signatureData,
                null
            )
            return KmmResult.success(verified)
        }
    }

}

@Suppress("UNCHECKED_CAST")
actual object CryptoUtils {

    actual fun extractPublicKeyFromX509Cert(it: ByteArray): CryptoPublicKey? {
        memScoped {
            val certData = CFBridgingRetain(toData(it)) as CFDataRef
            val certificate = SecCertificateCreateWithData(null, certData)
            val publicKey = SecCertificateCopyKey(certificate)
            val publicKeyData = SecKeyCopyExternalRepresentation(publicKey, null)
            val data = CFBridgingRelease(publicKeyData) as NSData
            return CryptoPublicKey.Ec.fromAnsiX963Bytes(EcCurve.SECP_256_R_1, data.toByteArray())
        }
    }

}

data class DefaultEphemeralKeyHolder(val publicKey: SecKeyRef, val privateKey: SecKeyRef? = null) : EphemeralKeyHolder {

    private val jsonWebKey = JsonWebKey.fromAnsiX963Bytes(
        JwkType.EC,
        EcCurve.SECP_256_R_1,
        (CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, null)) as NSData).toByteArray()
    )!!

    override fun toPublicJsonWebKey() = jsonWebKey

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
