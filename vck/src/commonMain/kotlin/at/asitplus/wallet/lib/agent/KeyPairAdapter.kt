package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer

/**
 * Abstracts the management of key material away from [CryptoService].
 */
interface KeyPairAdapter {
    val identifier: String

    val signer: Signer
    val signatureAlgorithm get() = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
    val publicKey: CryptoPublicKey get() = signer.publicKey

    /**
     * May be used in [at.asitplus.wallet.lib.cbor.CoseService] to transport the signing key for a COSE structure.
     * a `null` value signifies that raw public keys are used and no certificate is present
     */
    val certificate: X509Certificate?
    val jsonWebKey: JsonWebKey
    val coseKey: CoseKey

}

abstract class DefaultKeyPairAdapter(
    override val signer: Signer,
    extensions: List<X509CertificateExtension>
) : KeyPairAdapter {

    override val identifier: String get() = publicKey.didEncoded
    override val certificate =
        X509Certificate.generateSelfSignedCertificate(publicKey, signatureAlgorithm, extensions) {
            signer.sign(SignatureInput(it))
        }
    override val jsonWebKey: JsonWebKey
        get() = publicKey.toJsonWebKey()
    override val coseKey: CoseKey
        get() = publicKey.toCoseKey().getOrThrow()
}

/**
 * Generate a new key pair adapter with a random key, e.g. used in tests
 */
class EphemeralKeyPariAdapter(
    val key: EphemeralKey = EphemeralKey {
        ec {
            curve = ECCurve.SECP_256_R_1
            digests = setOf(Digest.SHA256)
        }
    }
) :
    DefaultKeyPairAdapter(key.signer(), listOf())

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
    }
    override val publicJsonWebKey: JsonWebKey?
        get() = key.publicKey.toJsonWebKey()

}
