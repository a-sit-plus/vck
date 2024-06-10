package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.pki.X509Certificate

/**
 * Abstracts the management of key material away from [CryptoService].
 */
interface KeyPairAdapter {
    val publicKey: CryptoPublicKey
    val identifier: String
    val signingAlgorithm: CryptoAlgorithm
    val certificate: X509Certificate?
    val jsonWebKey: JsonWebKey
    val coseKey: CoseKey
}

/**
 * Generate a new key pair adapter with a random key, e.g. used in tests
 */
expect fun RandomKeyPairAdapter(): KeyPairAdapter