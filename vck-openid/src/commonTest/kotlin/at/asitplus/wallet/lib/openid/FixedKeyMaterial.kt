package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.signerFor
import at.asitplus.wallet.lib.agent.SignerBasedKeyMaterial

/** Use only for testing! */
class FixedKeyMaterial(derEncoded: ByteArray) : SignerBasedKeyMaterial(
    signer = SignatureAlgorithm.ECDSAwithSHA256.signerFor(
        CryptoPrivateKey.EC.decodeFromDerSafe(derEncoded)
            .mapCatching { it as CryptoPrivateKey.EC.WithPublicKey }
            .getOrThrow()
    ).getOrThrow()
) {
    override suspend fun getCertificate(): X509Certificate? = null
}