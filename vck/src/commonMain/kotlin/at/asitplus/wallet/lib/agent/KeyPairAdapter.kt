package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Abstracts the management of key material away from [CryptoService].
 */
interface KeyPairAdapter {
    val publicKey: CryptoPublicKey
    val identifier: String
    val signingAlgorithm: X509SignatureAlgorithm

    /**
     * May be used in [at.asitplus.wallet.lib.cbor.CoseService] to transport the signing key for a COSE structure.
     * a `null` value signifies that raw public keys are used and no certificate is present
     */
    val certificate: X509Certificate?
    val jsonWebKey: JsonWebKey
    val coseKey: CoseKey
}

/**
 * Generate a new key pair adapter with a random key, e.g. used in tests
 */
expect fun RandomKeyPairAdapter(extensions: List<X509CertificateExtension> = listOf()): KeyPairAdapter
