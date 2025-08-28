package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidEncryptionParameters
import io.github.aakira.napier.Napier

/**
 * Server implementation to handle credential request decryption and credential response encryption using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 17, 2025-08-17.
 */
class IssuerEncryptionService(
    /** Encrypt credential response, if requested by client or [requireResponseEncryption] is set. */
    private val encryptCredentialResponse: EncryptJweFun = EncryptJwe(EphemeralKeyWithoutCert()),
    /** Whether to indicate in [metadataCredentialResponseEncryption] if credential response encryption is required. */
    internal val requireResponseEncryption: Boolean = false,
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithms: Set<JweAlgorithm> = setOf(JweAlgorithm.ECDH_ES),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = setOf(JweEncryption.A256GCM),
    /** Whether credential request encryption is required, also needs [decryptionKeyMaterial]. */
    internal val requireRequestEncryption: Boolean = false,
    /** Key to offer for credential request encryption. */
    private val decryptionKeyMaterial: KeyMaterial? = null,
    /** Used to decrypt the credential request sent by the client. */
    private val decryptCredentialRequest: DecryptJweFun? = decryptionKeyMaterial?.let { DecryptJwe(it) },
) {

    val metadataCredentialRequestEncryption = decryptionKeyMaterial?.let {
        SupportedAlgorithmsContainer(
            supportedAlgorithmsStrings = supportedJweAlgorithms.map { it.identifier }.toSet(),
            supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
            encryptionRequired = requireRequestEncryption,
            jsonWebKeySet = JsonWebKeySet(listOf(decryptionKeyMaterial.jsonWebKey))
        )
    }

    val metadataCredentialResponseEncryption = SupportedAlgorithmsContainer(
        supportedAlgorithmsStrings = supportedJweAlgorithms.map { it.identifier }.toSet(),
        supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
        encryptionRequired = requireResponseEncryption,
    )

    /** Decrypts credential requests from the client. */
    internal suspend fun decrypt(
        input: String,
    ): KmmResult<CredentialRequestParameters> = catching {
        if (decryptCredentialRequest == null)
            throw InvalidEncryptionParameters("Client sent encrypted request, we can't decode it")
        val jwe = JweEncrypted.deserialize(input).getOrElse {
            throw InvalidEncryptionParameters("Parsing of JWE failed", it)
        }.also { Napier.d("decrypt got $it") }
        val decrypted = decryptCredentialRequest(jwe).getOrElse {
            throw InvalidEncryptionParameters("Decryption of request failed", it)
        }.also { Napier.d("decrypt got $it") }
        joseCompliantSerializer.decodeFromString<CredentialRequestParameters>(decrypted.payload)
    }

    /** Encrypts the issued credential, if requested so by the client, or required by [requireResponseEncryption]. */
    internal fun encryptResponseIfNecessary(
        parameters: CredentialRequestParameters,
    ): (suspend (String) -> String) = { input: String ->
        parameters.credentialResponseEncryption?.let {
            it.jweEncryption?.let { jweEncryption ->
                Napier.d("encrypting response for ${it.jsonWebKey.keyId}")
                encryptCredentialResponse(
                    header = JweHeader(
                        algorithm = it.jweAlgorithm,
                        encryption = jweEncryption,
                        keyId = it.jsonWebKey.keyId,
                    ),
                    payload = input,
                    recipientKey = it.jsonWebKey,
                ).getOrThrow().serialize()
            } ?: throw InvalidEncryptionParameters("Unsupported enc: ${it.jweEncryptionString}")
        } ?: run {
            if (requireResponseEncryption)
                throw InvalidEncryptionParameters("Response encryption required, no params sent")
            else input
        }
    }

}