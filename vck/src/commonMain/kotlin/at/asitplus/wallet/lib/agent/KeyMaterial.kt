package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import io.github.aakira.napier.Napier
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Abstracts the management of key material away from cryptographic functions.
 */
interface KeyMaterial : Signer {
    val identifier: String

    fun getUnderLyingSigner(): Signer

    /**
     * May be used to transport the signing key for a COSE structure.
     * a `null` value signifies that raw public keys are used and no certificate is present
     */
    suspend fun getCertificate(): X509Certificate?

    val jsonWebKey: JsonWebKey get() = publicKey.toJsonWebKey(identifier)
}

abstract class KeyWithSelfSignedCert(
    private val extensions: List<X509CertificateExtension>,
    val customKeyId: String? = null,
    val lifetimeInSeconds: Long = 30,
) : KeyMaterial {
    override val identifier: String get() = customKeyId ?: publicKey.didEncoded
    private val crtMut = Mutex()
    private var _certificate: X509Certificate? = null

    override suspend fun getCertificate(): X509Certificate? {
        crtMut.withLock {
            if (_certificate == null) _certificate = X509Certificate.generateSelfSignedCertificate(
                publicKey,
                signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
                lifetimeInSeconds = lifetimeInSeconds,
                extensions = extensions,
            ) {
                sign(it).asKmmResult()
            }.onFailure { Napier.e("Could not self-sign Cert", it) }.getOrNull()
        }
        return _certificate
    }
}

/**
 * Generate new key material with a random key, and a self-signed certificate, e.g. used in tests
 */
class EphemeralKeyWithSelfSignedCert(
    val key: EphemeralKey = EphemeralKey {
        ec {
            curve = ECCurve.SECP_256_R_1
            digests = setOf(Digest.SHA256)
        }
    }.getOrThrow(),
    extensions: List<X509CertificateExtension> = listOf(),
    customKeyId: String? = null,
    lifetimeInSeconds: Long = 30,
) : KeyWithSelfSignedCert(extensions, customKeyId, lifetimeInSeconds), Signer by key.signer().getOrThrow() {
    override fun getUnderLyingSigner(): Signer = key.signer().getOrThrow()
}

/**
 * Generate new key material with a random key, e.g. used in tests
 */
class EphemeralKeyWithoutCert(
    val key: EphemeralKey = EphemeralKey {
        ec {
            curve = ECCurve.SECP_256_R_1
            digests = setOf(Digest.SHA256)
        }
    }.getOrThrow(),
    val customKeyId: String? = null,
) : KeyMaterial, Signer by key.signer().getOrThrow() {
    override val identifier: String = customKeyId ?: publicKey.didEncoded
    override fun getUnderLyingSigner(): Signer = key.signer().getOrThrow()
    override suspend fun getCertificate(): X509Certificate? = null
}

interface EphemeralKeyHolder {
    val publicJsonWebKey: JsonWebKey?
    val key: EphemeralKey
}

open class DefaultEphemeralKeyHolder(val crv: ECCurve) : EphemeralKeyHolder {
    override val key: EphemeralKey = EphemeralKey {
        ec {
            curve = crv
            digests = setOf(crv.nativeDigest)
        }
    }.getOrThrow()

    override val publicJsonWebKey: JsonWebKey?
        get() = key.publicKey.toJsonWebKey()

}

abstract class SignerBasedKeyMaterial(
    val signer: Signer,
    val customKeyId: String? = null,
) : KeyMaterial, Signer by signer {
    override val identifier = customKeyId ?: signer.publicKey.didEncoded

    override fun getUnderLyingSigner() = signer
}