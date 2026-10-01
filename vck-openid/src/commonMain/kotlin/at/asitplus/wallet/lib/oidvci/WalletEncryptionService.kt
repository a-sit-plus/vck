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
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidEncryptionParameters
import io.github.aakira.napier.Napier
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads

/**
 * Wallet implementation to handle credential request encryption and credential response decryption using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class WalletEncryptionService @JvmOverloads constructor(
    /** Whether to request credential response encryption from the issuer. */
    internal val requestResponseEncryption: Boolean = false,
    /** Whether to encrypt the credential request, if supported by the issuer.*/
    internal val requireRequestEncryption: Boolean = false,
    /** Encrypt credential request, if requested by the issuer. */
    private val encryptCredentialRequest: EncryptJweFun = EncryptJwe(),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES,
    /** Algorithm to fallback to for credential response encryption. */
    private val fallbackJweEncryptionAlgorithm: JweEncryption = JweEncryption.A256GCM,
    @Deprecated("Use [ephemeralEncryptionKeyService] instead")
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Creates one ephemeral encryption key per credential request. */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
    /** Used to decrypt the credential response sent by the issuer. */
    private val decryptCredentialResponse: DecryptJweFun? =
        DecryptJweWithEphemeralKey(ephemeralEncryptionKeyService),
) {

    init {
        require(supportedJweAlgorithm == JweAlgorithm.ECDH_ES) {
            "EphemeralEncryptionKeyService only supports ECDH-ES"
        }
    }

    internal suspend fun wrapCredentialRequest(
        input: CredentialRequestParameters,
        metadata: IssuerMetadata
    ): KmmResult<WalletService.CredentialRequest> = catching {
        if (metadata.shouldEncryptRequest(input)) {
            WalletService.CredentialRequest.Encrypted(
                request = encryptRequest(input, metadata).getOrThrow(),
                credentialResponseEncryptionKeyId = input.credentialResponseEncryption?.jsonWebKey?.keyId,
            )
        } else {
            WalletService.CredentialRequest.Plain(input)
        }
    }

    private fun IssuerMetadata.shouldEncryptRequest(input: CredentialRequestParameters): Boolean =
        credentialRequestEncryption?.encryptionRequired == true
                // OID4VCI: "Credential Request encryption MUST be used if the `credential_response_encryption`
                // parameter is included, to prevent it being substituted by an attacker"
                || input.credentialResponseEncryption != null
                || (requireRequestEncryption && canEncryptRequest())

    /** Whether the issuer has published a key that we can encrypt the credential request to. */
    private fun IssuerMetadata.canEncryptRequest(): Boolean =
        credentialRequestEncryption?.jsonWebKeySet?.keys?.getEncryptionTargetKey() != null

    /** Encrypts the credential request. */
    internal suspend fun encryptRequest(
        input: CredentialRequestParameters,
        metadata: IssuerMetadata,
    ): KmmResult<JweEncrypted> = catching {
        val recipientKey = metadata.credentialRequestEncryption?.jsonWebKeySet?.keys?.getEncryptionTargetKey()
            ?: throw InvalidEncryptionParameters("No recipient key found in metadata")
        val jweAlg = (recipientKey.algorithm as? JweAlgorithm?)
            ?: metadata.credentialRequestEncryption.selectAlgorithm()
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

    /**
     * Appends credential response encryption information to the request, with a key specific to this request,
     * see [ephemeralEncryptionKeyService].
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun credentialResponseEncryption(
        metadata: IssuerMetadata
    ): CredentialResponseEncryption? {
        val issuerSupport = metadata.credentialResponseEncryption ?: return null
        val encryptionRequired = issuerSupport.encryptionRequired == true
        if (!encryptionRequired && !requestResponseEncryption) return null

        if (!metadata.canEncryptRequest()) {
            if (encryptionRequired) throw InvalidEncryptionParameters(
                "Issuer requires credential response encryption, but published no key to encrypt the request with"
            )
            Napier.w("Not requesting credential response encryption: the request can't be encrypted")
            return null
        }
        val jweAlgorithm = issuerSupport.selectAlgorithm()
        val jweEncryption = issuerSupport.selectEncryption()
        if (jweAlgorithm == null || jweEncryption == null) {
            if (encryptionRequired) throw InvalidEncryptionParameters(
                "Issuer requires credential response encryption, but no supported algorithm combination exists"
            )
            Napier.w("Not requesting credential response encryption: no supported algorithm combination exists")
            return null
        }
        val key = ephemeralEncryptionKeyService.createKey()
        return CredentialResponseEncryption(
            jsonWebKey = key.toEncryptionJsonWebKey(),
            jweAlgorithm = null,
            jweEncryptionString = jweEncryption.identifier,
        )
    }

    /** Decrypts encrypted credential response from the issuer. */
    internal suspend fun decryptToCredentialResponse(
        input: String,
        expectedKeyId: String,
    ): KmmResult<CredentialResponseParameters> = catching {
        if (input.count { it == '.' } != 4)
            throw InvalidEncryptionParameters("Parsing of JWE failed, not five parts")
        val jwe = JweEncrypted.deserialize(input).getOrElse {
            throw InvalidEncryptionParameters("Parsing of JWE failed", it)
        }
        decryptToCredentialResponse(jwe, expectedKeyId).getOrThrow()
    }

    /** Decrypts encrypted credential response from the issuer. */
    internal suspend fun decryptToCredentialResponse(
        input: JweEncrypted,
        expectedKeyId: String,
    ): KmmResult<CredentialResponseParameters> = catching {
        if (input.header.keyId != expectedKeyId)
            throw InvalidEncryptionParameters("Credential response key does not match the credential request")
        if (decryptCredentialResponse == null)
            throw InvalidEncryptionParameters("Issuer sent encrypted response, we can't decode it")
        val decrypted = decryptCredentialResponse(input).getOrElse {
            throw InvalidEncryptionParameters("Decryption of response failed", it)
        }.also { Napier.d("decrypt got $it") }
        joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(decrypted.payload)
    }


}
