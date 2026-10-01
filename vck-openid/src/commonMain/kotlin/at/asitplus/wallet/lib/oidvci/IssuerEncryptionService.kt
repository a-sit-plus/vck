package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidEncryptionParameters
import io.github.aakira.napier.Napier
import kotlin.jvm.JvmOverloads

/**
 * Server implementation to handle credential request decryption and credential response encryption using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class IssuerEncryptionService @JvmOverloads constructor(
    /** Encrypt credential response, if requested by client or [requireResponseEncryption] is set. */
    private val encryptCredentialResponse: EncryptJweFun = EncryptJwe(),
    /** Whether to indicate in [metadataCredentialResponseEncryption] if credential response encryption is required. */
    internal val requireResponseEncryption: Boolean = false,
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithms: Set<JweAlgorithm> = setOf(JweAlgorithm.ECDH_ES),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = setOf(JweEncryption.A256GCM),
    /** Whether credential request encryption is required, also needs [decryptionKeyMaterial]. */
    internal val requireRequestEncryption: Boolean = false,
    /** Key to offer for credential request encryption. */
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Used to decrypt the credential request sent by the client. */
    private val decryptCredentialRequest: DecryptJweFun? = DecryptJwe(decryptionKeyMaterial),
) {

    /**
     * Advertised whenever we are able to decrypt credential requests. Requiring response encryption implies requiring
     * request encryption, since the client's response encryption key may only be sent in an encrypted request.
     */
    val metadataCredentialRequestEncryption = if (decryptCredentialRequest != null)
        SupportedAlgorithmsContainer(
            supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
            encryptionRequired = requireRequestEncryption || requireResponseEncryption,
            jsonWebKeySet = JsonWebKeySet(
                listOf(decryptionKeyMaterial.toEncryptionJsonWebKey())
            )
        )
    else null

    /** Advertised unconditionally: we can always encrypt a response to the key the client sends us. */
    val metadataCredentialResponseEncryption = SupportedAlgorithmsContainer(
        supportedAlgorithmsStrings = supportedJweAlgorithms.map { it.identifier }.toSet(),
        supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
        encryptionRequired = requireResponseEncryption,
    )

    /**
     * Rejects a credential request that should have been encrypted, as per OID4VCI: *"When encryption of a message was
     * required but the received message is unencrypted, it SHOULD be rejected"*, and *"Credential Request encryption
     * MUST be used if the `credential_response_encryption` parameter is included, to prevent it being substituted by
     * an attacker"*.
     */
    @Throws(OAuth2Exception::class)
    internal fun validateRequestEncryption(
        request: CredentialRequestParameters,
        hasBeenEncrypted: Boolean
    ) {
        if (hasBeenEncrypted) return
        if (requireRequestEncryption)
            throw InvalidEncryptionParameters("Credential request has not been encrypted")
        if (request.credentialResponseEncryption != null)
            throw InvalidEncryptionParameters(
                "Credential response encryption parameters may only be sent in an encrypted credential request"
            )
    }

    /** Decrypts credential requests from the client. */
    internal suspend fun decrypt(
        input: JweEncrypted,
    ): KmmResult<CredentialRequestParameters> = catching {
        if (decryptCredentialRequest == null)
            throw InvalidEncryptionParameters("Client sent encrypted request, we can't decode it")
        val decrypted = decryptCredentialRequest(input).getOrElse {
            throw InvalidEncryptionParameters("Decryption of request failed", it)
        }.also { Napier.d("decrypt got $it") }
        joseCompliantSerializer.decodeFromString<CredentialRequestParameters>(decrypted.payload)
    }

    /** Decrypts credential requests from the client. */
    internal suspend fun decrypt(
        input: String,
    ): KmmResult<CredentialRequestParameters> = catching {
        if (decryptCredentialRequest == null)
            throw InvalidEncryptionParameters("Client sent encrypted request, we can't decode it")
        val jwe = JweEncrypted.deserialize(input).getOrElse {
            throw InvalidEncryptionParameters("Parsing of JWE failed", it)
        }
        decrypt(jwe).getOrThrow()
    }

    internal suspend fun encryptResponse(
        response: CredentialResponseParameters,
        request: CredentialRequestParameters,
    ): CredentialIssuer.CredentialResponse =
        request.credentialResponseEncryption?.let {
            val recipientKey = it.jsonWebKey
            val jweAlg = (recipientKey.algorithm as? JweAlgorithm)
                ?: throw InvalidEncryptionParameters("Response encryption JWK has no supported alg")
            if (jweAlg !in supportedJweAlgorithms)
                throw InvalidEncryptionParameters("Unsupported alg: ${jweAlg.identifier}")
            val jweEnc = it.jweEncryption
                ?: throw InvalidEncryptionParameters("Unsupported enc: ${it.jweEncryptionString}")
            if (jweEnc !in supportedJweEncryptionAlgorithms)
                throw InvalidEncryptionParameters("Unsupported enc: ${jweEnc.identifier}")
            Napier.d("encrypting response for $recipientKey")
            CredentialIssuer.CredentialResponse.Encrypted(
                encryptCredentialResponse(
                    header = JweHeader(
                        algorithm = jweAlg,
                        encryption = jweEnc,
                        keyId = recipientKey.keyId,
                    ),
                    payload = joseCompliantSerializer.encodeToString(response),
                    recipientKey = recipientKey,
                ).getOrThrow()
            )
        } ?: run {
            if (requireResponseEncryption)
                throw InvalidEncryptionParameters("Response encryption required, no params sent")
            CredentialIssuer.CredentialResponse.Plain(response)
        }
}
