@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.ios

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithmPreHashed
import at.asitplus.signum.internals.CoreFoundationException
import at.asitplus.signum.internals.OwnedCFValue
import at.asitplus.signum.internals.createCFDictionary
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.giveToCF
import at.asitplus.signum.internals.manage
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.CFCryptoOperationFailed
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.os.UnlockPromptConfiguration
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.preHashedSignatureFormat
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.CPointerVarOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Foundation.NSData
import platform.LocalAuthentication.LAErrorAuthenticationFailed
import platform.LocalAuthentication.LAErrorBiometryLockout
import platform.LocalAuthentication.LAErrorDomain
import platform.LocalAuthentication.LAErrorUserCancel
import platform.LocalAuthentication.LAContext
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyIsAlgorithmSupported
import platform.Security.SecKeyRef
import platform.Security.SecItemCopyMatching
import platform.Security.errSecAuthFailed
import platform.Security.errSecItemNotFound
import platform.Security.errSecParam
import platform.Security.errSecSuccess
import platform.Security.errSecUserCanceled
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecMatchItemList
import platform.Security.kSecKeyOperationTypeSign
import platform.Security.kSecReturnRef
import platform.Security.kSecUseAuthenticationContext
import platform.Security.kSecUseAuthenticationUI
import platform.Security.kSecUseAuthenticationUIAllow

object SignerAdapter {

    @Suppress("UNCHECKED_CAST")
    fun fromSecKey(privateKey: SecKeyRef?, algorithm: SignatureAlgorithm): KmmResult<Signer> =
        fromSecKey(
            privateKey,
            algorithm,
            UnlockPromptConfiguration.defaultMessage,
            UnlockPromptConfiguration.defaultCancelText,
        )

    @Suppress("UNCHECKED_CAST")
    fun fromSecKey(
        privateKey: SecKeyRef?,
        algorithm: SignatureAlgorithm,
        unlockMessage: String,
        cancelMessage: String,
    ): KmmResult<Signer> = catching {
        val key = requireNotNull(privateKey) { "privateKey must not be null" }
        require(SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeSign, algorithm.secKeyAlgorithmPreHashed)) {
            "SecKey does not support $algorithm"
        }
        val retainedKey = (CFRetain(key) as SecKeyRef).manage()
        val publicKey = corecall { SecKeyCopyPublicKey(retainedKey.value) }.manage()
        val publicKeyBytes = corecall { SecKeyCopyExternalRepresentation(publicKey.value, error) }
            .takeFromCF<NSData>().toByteArray()

        when (val parsedPublicKey = CryptoPublicKey.fromIosEncoded(publicKeyBytes)) {
            is CryptoPublicKey.EC -> {
                val ecAlgorithm = algorithm as? SignatureAlgorithm.ECDSA
                    ?: throw IllegalArgumentException("EC SecKey requires an ECDSA algorithm")
                require(ecAlgorithm.requiredCurve == null || ecAlgorithm.requiredCurve == parsedPublicKey.curve) {
                    "ECDSA curve does not match SecKey"
                }
                SecKeySigner.EC(retainedKey, parsedPublicKey, ecAlgorithm, unlockMessage, cancelMessage)
            }
            is CryptoPublicKey.RSA -> SecKeySigner.RSA(
                retainedKey,
                parsedPublicKey,
                algorithm as? SignatureAlgorithm.RSA
                    ?: throw IllegalArgumentException("RSA SecKey requires an RSA algorithm"),
                unlockMessage,
                cancelMessage,
            )
        }
    }
}

private sealed class SecKeySigner(
    protected val privateKey: OwnedCFValue<SecKeyRef>,
    private val unlockMessage: String,
    private val cancelMessage: String,
) : Signer {
    final override val mayRequireUserUnlock = true

    final override suspend fun sign(data: SignatureInput): SignatureResult<*> = try {
        val digest = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow().data.single().toNSData()
        val signature = memScoped {
            val item = alloc<CPointerVarOf<SecKeyRef>>()
            val itemListValues = allocArray<COpaquePointerVar>(1).also { it[0] = privateKey.value.reinterpret() }
            val itemList = CFArrayCreate(null, itemListValues, 1, kCFTypeArrayCallBacks.ptr)!!
                .also { defer { CFRelease(it) } }
            val context = LAContext().apply {
                localizedReason = unlockMessage
                localizedCancelTitle = cancelMessage
            }
            val query = createCFDictionary {
                kSecClass mapsTo kSecClassKey
                kSecMatchItemList mapsTo itemList
                kSecReturnRef mapsTo true
                kSecUseAuthenticationContext mapsTo context
                kSecUseAuthenticationUI mapsTo kSecUseAuthenticationUIAllow
            }
            val signingKey: SecKeyRef = when (val status = SecItemCopyMatching(query, item.ptr.reinterpret())) {
                errSecSuccess -> requireNotNull(item.value)
                    .also { defer { CFRelease(it) } }
                errSecItemNotFound, errSecParam -> privateKey.value // transient SecKey
                else -> throw CFCryptoOperationFailed("retrieve private key", status)
            }
            corecall {
                SecKeyCreateSignature(signingKey, signatureAlgorithm.secKeyAlgorithmPreHashed, digest.let(::giveToCF), error)
            }.takeFromCF<NSData>().toByteArray()
        }

        SignatureResult.Success(when (val key = publicKey) {
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signature).withCurve(key.curve)
            is CryptoPublicKey.RSA -> CryptoSignature.RSA(signature)
        })
    } catch (exception: CoreFoundationException) {
        if (exception.nsError.domain == LAErrorDomain && when (exception.nsError.code) {
                LAErrorUserCancel, LAErrorAuthenticationFailed, LAErrorBiometryLockout -> true
                else -> false
            }) {
            SignatureResult.Failure(UnlockFailed(exception.nsError.localizedDescription, exception))
        } else {
            SignatureResult.Error(exception)
        }
    } catch (exception: CFCryptoOperationFailed) {
        if (exception.osStatus == errSecUserCanceled || exception.osStatus == errSecAuthFailed) {
            SignatureResult.Failure(UnlockFailed(exception.message, exception))
        } else {
            SignatureResult.Error(exception)
        }
    } catch (exception: Throwable) {
        SignatureResult.FromException(exception)
    }

    class EC(
        privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: CryptoPublicKey.EC,
        override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
        unlockMessage: String,
        cancelMessage: String,
    ) : SecKeySigner(privateKey, unlockMessage, cancelMessage), Signer.ECDSA {
        @SecretExposure
        override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.EC.WithPublicKey> =
            KmmResult.failure(UnsupportedOperationException("SecKey-backed private keys cannot be exported"))

        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH): KmmResult<ByteArray> =
            KmmResult.failure(UnsupportedOperationException("SecKeySigner only supports signing"))
    }

    class RSA(
        privateKey: OwnedCFValue<SecKeyRef>,
        override val publicKey: CryptoPublicKey.RSA,
        override val signatureAlgorithm: SignatureAlgorithm.RSA,
        unlockMessage: String,
        cancelMessage: String,
    ) : SecKeySigner(privateKey, unlockMessage, cancelMessage), Signer.RSA {
        @SecretExposure
        override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.RSA> =
            KmmResult.failure(UnsupportedOperationException("SecKey-backed private keys cannot be exported"))
    }
}
