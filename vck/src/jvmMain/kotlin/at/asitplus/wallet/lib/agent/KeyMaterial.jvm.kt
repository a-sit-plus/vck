package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.JKSProvider
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.runBlocking
import java.security.KeyStore
import kotlin.random.Random

/**
 * [SignKeyMaterial] based on an initialized, loaded [KeyStore] object.
 * @param keyAlias non-null alias of the private key used for signing
 * @param providerName optional name of the JCA provider to use
 * @param privateKeyPassword optional private key password
 * @param certAlias optional alias for the certificate to return when invoking [getCertificate]
 * @param customKeyId identifier to use, with a default random value
 */
class KeyStoreMaterial
@JvmOverloads constructor(
    private val keyStore: KeyStore,
    keyAlias: String,
    privateKeyPassword: CharArray,
    providerName: String? = null,
    private val certAlias: String? = null,
    customKeyId: String = Random.nextBytes(8).encodeToString(Base16Strict).lowercase(),
) : SignerBasedKeyMaterial(
    signer = runBlocking {
        JKSProvider {
            withBackingObject { store = keyStore }
        }.getOrThrow().getSignerForKey(keyAlias) {
            this.privateKeyPassword = privateKeyPassword
            provider = providerName
        }.getOrThrow()
    },
    customKeyId = customKeyId
) {
    override suspend fun getCertificate(): X509Certificate? =
        certAlias?.let { X509Certificate.decodeFromByteArray(keyStore.getCertificate(it).encoded) }

}

/**
 * [SignKeyMaterial] based on an initialized, loaded [KeyStore] object, which will use [PublishedKeyMaterial].
 * @param keyAlias non-null alias of the private key used for signing
 * @param providerName optional name of the JCA provider to use
 * @param privateKeyPassword optional private key password
 * @param certAlias optional alias for the certificate to return when invoking [getCertificate]
 * @param keySetUrl URL where this key is published
 * @param customKeyId identifier for the key set published under [keySetUrl]
 */
class PublishedKeyStoreMaterial
@JvmOverloads constructor(
    private val keyStore: KeyStore,
    keyAlias: String,
    privateKeyPassword: CharArray,
    providerName: String? = null,
    private val certAlias: String? = null,
    keySetUrl: String?,
    customKeyId: String,
) : SignerBasedPublishedKeyMaterial(
    signer = runBlocking {
        JKSProvider {
            withBackingObject { store = keyStore }
        }.getOrThrow().getSignerForKey(keyAlias) {
            this.privateKeyPassword = privateKeyPassword
            provider = providerName
        }.getOrThrow()
    },
    customKeyId = customKeyId,
    keySetUrl = keySetUrl,
) {
    override suspend fun getCertificate(): X509Certificate? =
        certAlias?.let { X509Certificate.decodeFromByteArray(keyStore.getCertificate(it).encoded) }

}