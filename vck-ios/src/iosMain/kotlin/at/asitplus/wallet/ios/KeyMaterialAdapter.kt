@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.ios

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SignerBasedKeyMaterial
import platform.Security.SecKeyRef

private class SecKeyMaterial(signer: Signer) : SignerBasedKeyMaterial(signer) {
    override suspend fun getCertificate(): X509Certificate? = null
}

/** Creates [KeyMaterial] for a P-256 `SecKey`, e.g. held in the Keychain or Secure Enclave, see [SignerAdapter]. */
object KeyMaterialAdapter {
    fun fromSecKey(privateKey: SecKeyRef?): KmmResult<KeyMaterial> = catching {
        SecKeyMaterial(
            SignerAdapter.fromSecKey(privateKey, SignatureAlgorithm.ECDSAwithSHA256).getOrThrow()
        )
    }
}
