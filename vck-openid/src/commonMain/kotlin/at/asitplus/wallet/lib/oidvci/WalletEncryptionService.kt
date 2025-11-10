package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseEncryption
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.symmetric.isAuthenticated
import at.asitplus.signum.indispensable.symmetric.requiresNonce
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidEncryptionParameters
import io.github.aakira.napier.Napier

/**
 * Wallet implementation to handle credential request encryption and credential response decryption using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class WalletEncryptionService(
    /** Whether to request credential response encryption */
    internal val requestEncryption: Boolean = false,
    /** Encrypt credential request, if requested by the issuer or [requestEncryption] is set. */
    private val encryptCredentialRequest: EncryptJweFun = EncryptJwe(EphemeralKeyWithoutCert()),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES,
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweEncryptionAlgorithm: JweEncryption = JweEncryption.A256GCM,
    /** Key to offer for credential response encryption. */
    private val decryptionKeyMaterial: KeyMaterial? = null,
    /** Used to decrypt the credential response sent by the issuer. */
    private val decryptCredentialResponse: DecryptJweFun? = decryptionKeyMaterial?.let { DecryptJwe(it) },
) {

    /** Encrypts the credential request. */
    internal suspend fun encrypt(
        input: CredentialRequestParameters,
        metadata: IssuerMetadata,
    ): KmmResult<JweEncrypted> = catching {
        val recipientKey = metadata.credentialRequestEncryption?.jsonWebKeySet?.keys?.firstOrNull()
            ?: throw InvalidEncryptionParameters("No recipient key found in metadata")
        encryptCredentialRequest(
            header = JweHeader(
                algorithm = metadata.credentialRequestEncryption.selectAlgorithm(),
                encryption = metadata.credentialRequestEncryption.selectEncryption()
            ),
            payload = joseCompliantSerializer.encodeToString(input),
            recipientKey = recipientKey
        ).getOrElse {
            throw InvalidEncryptionParameters("Failed to encrypt", it)
        }
    }

    /** Fallback to [supportedJweAlgorithm] and let's see if issuer can decrypt it. */
    private fun SupportedAlgorithmsContainer?.selectAlgorithm(): JweAlgorithm =
        this?.supportedAlgorithms?.filterIsInstance<JweAlgorithm>()?.firstOrNull {
            it == supportedJweAlgorithm
        } ?: supportedJweAlgorithm

    /** Fallback to [supportedJweEncryptionAlgorithm] and let's see if issuer can decrypt it. */
    private fun SupportedAlgorithmsContainer?.selectEncryption(): JweEncryption =
        this?.supportedEncryptionAlgorithms?.firstOrNull {
            it == supportedJweEncryptionAlgorithm
        } ?: this?.supportedEncryptionAlgorithms?.firstOrNull {
            it.algorithm.requiresNonce() && it.algorithm.isAuthenticated()
        } ?: supportedJweEncryptionAlgorithm

    /** Appends credential response encryption information to the request. */
    internal fun credentialResponseEncryption(metadata: IssuerMetadata): CredentialResponseEncryption? =
        if (requestEncryption && decryptionKeyMaterial != null && metadata.credentialResponseEncryption != null) {
            CredentialResponseEncryption(
                jsonWebKey = decryptionKeyMaterial.jsonWebKey,
                jweAlgorithm = supportedJweAlgorithm,
                jweEncryptionString = supportedJweEncryptionAlgorithm.identifier,
            )
        } else null

    /** Decrypts encrypted credentials (strings in the credential response) from the issuer. */
    internal suspend fun decrypt(
        input: String,
    ): KmmResult<String> = catching {
        if (input.count { it == '.' } != 4)
            return@catching input
        if (decryptCredentialResponse == null)
            throw InvalidEncryptionParameters("Issuer sent encrypted response, we can't decode it")
        val jwe = JweEncrypted.deserialize(input).getOrElse {
            throw InvalidEncryptionParameters("Parsing of JWE failed", it)
        }.also { Napier.d("decrypt got $it") }
        val decrypted = decryptCredentialResponse(jwe).getOrElse {
            throw InvalidEncryptionParameters("Decryption of response failed", it)
        }.also { Napier.d("decrypt got $it") }
        decrypted.payload
    }

}