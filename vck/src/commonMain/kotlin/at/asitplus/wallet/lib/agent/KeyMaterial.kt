package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.mac.mac
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.Signer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.random.Random

interface CoseKeyMaterial {
    val identifier: String
}

/**
 * Abstracts the management of key material away from cryptographic functions.
 */
interface KeyMaterial : CoseKeyMaterial, Signer {
    fun getUnderLyingSigner(): Signer

    /**
     * May be used to transport the signing key for a COSE structure.
     * a `null` value signifies that raw public keys are used and no certificate is present
     */
    suspend fun getCertificate(): X509Certificate?

    val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey(null)
}

interface SymmetricKeyMaterial : CoseKeyMaterial {
    val key: ByteArray
    val algorithm: HMAC

    suspend fun mac(data: ByteArray) : ByteArray
}

class EphemeralHmacKey(
    override val identifier: String = Random.nextBytes(8).encodeToString(Base16Strict).lowercase(),
    override val algorithm: HMAC = HMAC.SHA256,
    override val key: ByteArray
) : SymmetricKeyMaterial {
    override suspend fun mac(data: ByteArray): ByteArray = algorithm.mac(key, data).getOrThrow()
}

/**
 * Key material referenced by a key id in [identifier], which can be fetched by clients from [keySetUrl].
 */
interface PublishedKeyMaterial : KeyMaterial {
    /** Can be used by clients to look up this key in a [at.asitplus.signum.indispensable.josef.JsonWebKeySet]. */
    val keySetUrl: String?

    override val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey(identifier)
}

abstract class KeyWithSelfSignedCert(
    private val extensions: List<X509CertificateExtension>,
    private val customKeyId: String,
    private val lifetimeInSeconds: Long,
) : KeyMaterial {
    override val identifier: String get() = customKeyId
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
    customKeyId: String = Random.nextBytes(8).encodeToString(Base16Strict).lowercase(),
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
    val customKeyId: String = Random.nextBytes(8).encodeToString(Base16Strict).lowercase(),
) : KeyMaterial, Signer by key.signer().getOrThrow() {
    override val identifier: String = customKeyId
    override fun getUnderLyingSigner(): Signer = key.signer().getOrThrow()
    override suspend fun getCertificate(): X509Certificate? = null
}

/**
 * Key that will be referenced by its [getCertificate] or the [jsonWebKey] directly embedded in proofs.
 */
abstract class SignerBasedKeyMaterial(
    val signer: Signer,
    val customKeyId: String = Random.nextBytes(8).encodeToString(Base16Strict).lowercase(),
) : KeyMaterial, Signer by signer {
    override val identifier = customKeyId
    override fun getUnderLyingSigner() = signer
}

/**
 * Key that will be referenced by [customKeyId] in the key set published under [keySetUrl],
 * which will both be embedded in proofs.
 */
abstract class SignerBasedPublishedKeyMaterial(
    val signer: Signer,
    val customKeyId: String,
    override val keySetUrl: String?,
) : PublishedKeyMaterial, Signer by signer {
    override val identifier = customKeyId
    override fun getUnderLyingSigner() = signer
}