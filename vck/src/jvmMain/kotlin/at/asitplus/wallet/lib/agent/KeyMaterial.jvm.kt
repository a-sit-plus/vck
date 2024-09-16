package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.JKSProvider
import kotlinx.coroutines.runBlocking
import java.security.KeyStore

/**
 * [KeyMaterial] based on an initialized, loaded [KeyStore] object.
 * @param keyAlias non-null alias of the private key used for signing
 * @param providerName nullable. Can be used to optionally specify a provider
 * @param privateKeyPassword optional (i.e. nullable) private key password
 * @param certAlias optional(i.e. nullable) alias for the certificate to return when invoking [getCertificate]
 *
 */
class KeyStoreyMaterial
@JvmOverloads constructor(
    val keyStore: KeyStore,
    keyAlias: String,
    privateKeyPassword: CharArray,
    providerName: String? = null,
    private val certAlias: String? = null
) : SignerBasedKeyMaterial(
    runBlocking {
        JKSProvider {
            withBackingObject { store = keyStore }
        }.getOrThrow().getSignerForKey(keyAlias) {
            this.privateKeyPassword = privateKeyPassword
            provider = providerName
        }.getOrThrow()
    }) {
    override suspend fun getCertificate(): X509Certificate? =
        certAlias?.let { X509Certificate.decodeFromByteArray(keyStore.getCertificate(it).encoded) }

}