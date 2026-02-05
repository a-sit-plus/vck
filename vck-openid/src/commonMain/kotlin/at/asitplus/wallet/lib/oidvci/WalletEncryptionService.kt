package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseEncryption
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.signum.indispensable.josef.JsonWebKey
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
    /** Whether to request credential response encryption from the issuer. */
    internal val requestResponseEncryption: Boolean = false,
    /** Whether to encrypt the credential request, if supported by the issuer.*/
    internal val requireRequestEncryption: Boolean = false,
    /** Encrypt credential request, if requested by the issuer. */
    private val encryptCredentialRequest: EncryptJweFun = EncryptJwe(EphemeralKeyWithoutCert()),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES,
    /** Algorithm to fallback to for credential response encryption. */
    private val fallbackJweEncryptionAlgorithm: JweEncryption = JweEncryption.A256GCM,
    /** Key to offer for credential response encryption. */
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Used to decrypt the credential response sent by the issuer. */
    private val decryptCredentialResponse: DecryptJweFun? = DecryptJwe(decryptionKeyMaterial),
) {

    internal suspend fun wrapCredentialRequest(
        input: CredentialRequestParameters,
        metadata: IssuerMetadata
    ): KmmResult<WalletService.CredentialRequest> = catching {
        if (metadata.shouldEncryptRequest()) {
            WalletService.CredentialRequest.Encrypted(encryptRequest(input, metadata).getOrThrow())
        } else {
            WalletService.CredentialRequest.Plain(input)
        }
    }

    private fun IssuerMetadata.shouldEncryptRequest(): Boolean =
        credentialRequestEncryption?.encryptionRequired == true ||
                (requireRequestEncryption && credentialRequestEncryption?.jsonWebKeySet != null)

    /** Encrypts the credential request. */
    internal suspend fun encryptRequest(
        input: CredentialRequestParameters,
        metadata: IssuerMetadata,
    ): KmmResult<JweEncrypted> = catching {
        val recipientKey = metadata.credentialRequestEncryption?.jsonWebKeySet?.keys?.firstOrNull()
            ?: throw InvalidEncryptionParameters("No recipient key found in metadata")
        val jweAlg = metadata.credentialRequestEncryption.selectAlgorithm()
            ?: (recipientKey.algorithm as? JweAlgorithm?)
            ?: throw InvalidEncryptionParameters("No supported algorithm found in metadata")
        val jweEnc = metadata.credentialRequestEncryption.selectEncryption()
            ?: fallbackJweEncryptionAlgorithm
        encryptCredentialRequest(
            header = JweHeader(
                algorithm = jweAlg,
                encryption = jweEnc,
                keyId = recipientKey.keyId
            ),
            payload = joseCompliantSerializer.encodeToString(input),
            recipientKey = recipientKey
        ).getOrElse {
            throw InvalidEncryptionParameters("Failed to encrypt", it)
        }
    }

    /** Try to find a matching algorithm from issuer's metadata. */
    private fun SupportedAlgorithmsContainer?.selectAlgorithm(): JweAlgorithm? =
        this?.supportedAlgorithms?.filterIsInstance<JweAlgorithm>()?.firstOrNull {
            it == supportedJweAlgorithm
        }

    /** Try to find a matching encryption algorithm from issuer's metadata. */
    private fun SupportedAlgorithmsContainer?.selectEncryption(): JweEncryption? =
        this?.supportedEncryptionAlgorithms?.firstOrNull {
            it == fallbackJweEncryptionAlgorithm
        } ?: this?.supportedEncryptionAlgorithms?.firstOrNull {
            it.algorithm.requiresNonce() && it.algorithm.isAuthenticated()
        }

    /** Appends credential response encryption information to the request. */
    internal fun credentialResponseEncryption(
        metadata: IssuerMetadata
    ): CredentialResponseEncryption? = if (metadata.credentialResponseEncryption != null)
        if (requestResponseEncryption || metadata.credentialResponseEncryption?.encryptionRequired == true) {
            CredentialResponseEncryption(
                jsonWebKey = decryptionKeyMaterial.jsonWebKey.forEncryption(),
                jweAlgorithm = metadata.credentialResponseEncryption?.selectAlgorithm()
                    ?: supportedJweAlgorithm,
                jweEncryption = metadata.credentialResponseEncryption?.selectEncryption()
                    ?: fallbackJweEncryptionAlgorithm,
            )
        } else null
    else null

    /** Decrypts encrypted credential response from the issuer. */
    internal suspend fun decryptToCredentialResponse(
        input: String,
    ): KmmResult<CredentialResponseParameters> = catching {
        if (input.count { it == '.' } != 4)
            throw InvalidEncryptionParameters("Parsing of JWE failed, not five parts")
        val jwe = JweEncrypted.deserialize(input).getOrElse {
            throw InvalidEncryptionParameters("Parsing of JWE failed", it)
        }
        decryptToCredentialResponse(jwe).getOrThrow()
    }

    /** Decrypts encrypted credential response from the issuer. */
    internal suspend fun decryptToCredentialResponse(
        input: JweEncrypted,
    ): KmmResult<CredentialResponseParameters> = catching {
        if (decryptCredentialResponse == null)
            throw InvalidEncryptionParameters("Issuer sent encrypted response, we can't decode it")
        val decrypted = decryptCredentialResponse(input).getOrElse {
            throw InvalidEncryptionParameters("Decryption of response failed", it)
        }.also { Napier.d("decrypt got $it") }
        joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(decrypted.payload)
    }

    // should always be ecdh-es for encryption
    private fun JsonWebKey.forEncryption(): JsonWebKey =
        this.copy(algorithm = JweAlgorithm.ECDH_ES, publicKeyUse = "enc")

}
