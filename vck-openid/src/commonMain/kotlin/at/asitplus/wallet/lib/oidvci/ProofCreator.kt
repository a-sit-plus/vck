package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient.KeyAttestationInput
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * Creates the `proofs` of a credential request (OpenID4VCI 1.0, 8.2) of one proof type (Appendix F), which provide the
 * key material the issued credential will be bound to (8.1).
 *
 * [OpenId4VciClient] asks its proof creators in the order given and uses the first proof created, so list them in the
 * order of preference: the issuer accepts each of its `proof_types_supported`, and the request carries exactly one
 * (8.2). If a creator fails, the next one is asked; the credential request fails if none creates a proof although the
 * issuer lists proof types, and is sent without `proofs` only if it lists none (12.2.4).
 */
interface ProofCreator {
    /**
     * Creates the proof for a credential of [credentialFormat] to be requested from [credentialIssuer].
     *
     * @param credentialIssuer the Credential Issuer Identifier, i.e. the audience of the proof (8.2)
     * @param credentialFormat the configuration of the requested credential, whose
     * [SupportedCredentialFormat.supportedProofTypes] lists the proof types the issuer accepts for it
     * @param clientId the `client_id` of the OAuth 2.0 client requesting the credential
     * @param clientNonce the `c_nonce` from the Nonce Endpoint of the issuer (7.2), if it has one
     * @return `null` if the issuer does not accept the proof type of this creator for [credentialFormat], or a failure
     * if the proof can not be created, e.g. without a key attestation the issuer requires; either way, the next creator
     * is asked
     */
    suspend fun invoke(
        credentialIssuer: String,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?,
    ): KmmResult<CredentialRequestProofContainer?>
}

/**
 * Creates proofs of the `jwt` proof type (OpenID4VCI 1.0, Appendix F.1): a JWT of type `openid4vci-proof+jwt`, signed
 * with [keyMaterial], the key the issued credential will be bound to, which the header references as `jwk` or `kid`,
 * see [selectProofJwtKeyBinding]. Its payload carries the `client_id` as `iss`, the Credential Issuer Identifier as
 * `aud`, the `c_nonce` as `nonce`, and as `iat` the time of [clock] three minutes ago, to tolerate the clock skew of
 * the issuer.
 *
 * If the issuer requires a key attestation for the `jwt` proof type (`key_attestations_required`), the proof carries
 * one in its `key_attestation` header (Appendix D), loaded with [loadKeyAttestation]. Then creating the proof fails
 * without [loadKeyAttestation], if [loadKeyAttestation] fails, or if the key attestation does not attest
 * [keyMaterial] as its first key.
 *
 * Creates no proof if the issuer does not accept the `jwt` proof type for the requested credential.
 */
class JwtProofCreator(
    /** Used to prove possession of the key material for [CredentialRequestProofContainer], i.e., the holder key. */
    private val keyMaterial: KeyMaterial,
    /** Optionally load key attestation when the issuer metadata requires it. */
    private val loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsCompactTyped<KeyAttestationJwt>>)? = null,
    /**
     * Selects the key binding to embed in the [JwsHeader] of a credential request proof JWT,
     * as defined in the OpenID for Verifiable Credential Issuance specification.
     *
     * This function determines how the holder's key is referenced in the proof JWT header,
     * by selecting between two mutually exclusive binding mechanisms:
     *
     * - **`jwk`** ([JwsHeader.jsonWebKey]): embeds the [JsonWebKey] inline in the header,
     *   suitable when the holder has no associated DID.
     * - **`kid`** ([JwsHeader.keyId]): embeds a DID URL string in the header,
     *   identifying a specific key within the holder's DID Document.
     *
     * The lambda receives the current [KeyMaterial] and must return a [Pair] where:
     * - the **first** element is the [JsonWebKey] to embed as the `jwk` header parameter, or `null`,
     * - the **second** element is the DID URL string to embed as the `kid` header parameter, or `null`.
     *
     * Exactly **one** of the two values must be non-null, as `jwk` and `kid` are mutually exclusive:
     * - Returning **both non-null** will throw an [IllegalArgumentException] during proof creation.
     * - Returning **both null** will throw an [IllegalArgumentException] during proof creation.
     *
     * Defaults to selecting the [JsonWebKey] from [KeyMaterial.jsonWebKey] as the `jwk` binding,
     * which is suitable when no DID is associated with the holder.
     *
     * @see JwsHeader.jsonWebKey
     * @see JwsHeader.keyId
     */
    // Replace with a sealed interface?
    private val selectProofJwtKeyBinding: (suspend (KeyMaterial) -> Pair<JsonWebKey?, String?>) = { key ->
        Pair(key.jsonWebKey, null)
    },
    /** Clock to use for proof generation. */
    private val clock: Clock = Clock.System,
) : ProofCreator {
    override suspend fun invoke(
        credentialIssuer: String,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?,
    ): KmmResult<CredentialRequestProofContainer?> = catching {
        credentialFormat.supportedProofTypes?.get(ProofTypes.JWT)?.let { type ->
            createCredentialRequestProofJwt(
                clientNonce = clientNonce,
                credentialIssuer = credentialIssuer,
                clientId = clientId,
                keyAttestationRequired = type.keyAttestationRequired,
                supportedAlgorithms = type.supportedSigningAlgorithms,
            )
        }
    }

    internal suspend fun createCredentialRequestProofJwt(
        clientNonce: String?,
        credentialIssuer: String?,
        keyAttestationRequired: KeyAttestationRequired? = null,
        supportedAlgorithms: Collection<String>? = null,
        clientId: String,
    ): CredentialRequestProofContainer {
        if (keyAttestationRequired != null && loadKeyAttestation == null) {
            throw IllegalArgumentException("Key attestation required, none provided")
        }
        val keyAttestation: JwsCompactTyped<KeyAttestationJwt>? = if (keyAttestationRequired != null) {
            loadKeyAttestation?.invoke(
                KeyAttestationInput(
                    credentialIssuer = credentialIssuer,
                    clientNonce = clientNonce,
                    supportedAlgorithms = supportedAlgorithms,
                    preferredKeyStorageStatusPeriod = keyAttestationRequired.preferredTtl,
                    requirements = keyAttestationRequired
                )
            )?.getOrElse { throw IllegalArgumentException("Key attestation required, none provided", it) }
        } else null
        keyAttestation?.requireKeyMaterialAtAttestedKeyIndex0()

        // To be refactored once signJwt is not passed in the constructor but to this function
        return CredentialRequestProofContainer(
            jwt = setOf(
                SignJwt<JsonWebToken>(keyMaterial, headerModifier(keyAttestation)).invoke(
                    type = OpenIdConstants.PROOF_JWT_TYPE,
                    payload = JsonWebToken(
                        issuer = clientId, // omit when token was pre-authn?
                        audience = credentialIssuer,
                        // Apply a bit of clock skew to avoid getting rejected by the issuer
                        issuedAt = clock.now().truncateToSeconds() - 3.minutes,
                        nonce = clientNonce,
                    ),
                    serializer = JsonWebToken.serializer(),
                ).getOrThrow().jws
            )
        )
    }

    private fun JwsCompactTyped<KeyAttestationJwt>.requireKeyMaterialAtAttestedKeyIndex0() {
        val attestedKey = payload.attestedKeys.firstOrNull()
            ?: throw IllegalArgumentException("Key attestation required, none provided")
        if (attestedKey.jwkThumbprintPlain != keyMaterial.jsonWebKey.jwkThumbprintPlain) {
            throw IllegalArgumentException("Key attestation attested_keys[0] must match credential proof signing key")
        }
    }

    private val JsonWebKey.jwkThumbprintPlain: String
        get() = jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")

    private fun headerModifier(
        keyAttestation: JwsCompactTyped<KeyAttestationJwt>?
    ): JwsHeaderIdentifierFun = { header: JwsHeader, key: KeyMaterial ->
        val (jsonWebKey, keyId) = selectProofJwtKeyBinding.invoke(key)
        when {
            jsonWebKey != null && keyId.isNullOrEmpty() ->
                header.copy(jsonWebKey = jsonWebKey, keyAttestation = keyAttestation?.jws)

            jsonWebKey == null && !keyId.isNullOrEmpty() ->
                header.copy(keyId = keyId, keyAttestation = keyAttestation?.jws)

            jsonWebKey != null && !keyId.isNullOrEmpty() ->
                throw IllegalArgumentException(
                    "Key binding conflict: both 'jwk' and 'kid' are set, only one must be provided as per OID4VCI spec."
                )

            else -> // same as jsonWebKey == null && keyId.isNullOrEmpty()
                throw IllegalArgumentException(
                    "Key binding missing: neither 'jwk' nor 'kid' is set, exactly one must be provided as per OID4VCI spec."
                )
        }
    }

}

/**
 * Creates proofs of the `attestation` proof type (OpenID4VCI 1.0, Appendix F.3): exactly one key attestation in JWT
 * format (Appendix D.1), loaded with [loadKeyAttestation], without a proof of possession of the attested keys. The
 * `c_nonce` is passed to [loadKeyAttestation] as [KeyAttestationInput.clientNonce], as it has to be the `nonce` of the
 * key attestation if the issuer has a Nonce Endpoint (Appendix F.3).
 *
 * Creating the proof fails if [loadKeyAttestation] fails. Creates no proof if the issuer does not accept the
 * `attestation` proof type for the requested credential.
 */
class AttestationProofCreator(
    /** Load the key attestation for the proof. */
    private val loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsCompactTyped<KeyAttestationJwt>>),
) : ProofCreator {
    override suspend fun invoke(
        credentialIssuer: String,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?,
    ): KmmResult<CredentialRequestProofContainer?> = catching {
        credentialFormat.supportedProofTypes?.get(ProofTypes.ATTESTATION)?.let { type ->
            createCredentialRequestProofAttestation(
                clientNonce = clientNonce,
                credentialIssuer = credentialIssuer,
                keyAttestationRequired = type.keyAttestationRequired,
                supportedAlgorithms = type.supportedSigningAlgorithms,
            )
        }
    }

    internal suspend fun createCredentialRequestProofAttestation(
        clientNonce: String?,
        credentialIssuer: String?,
        keyAttestationRequired: KeyAttestationRequired? = null,
        supportedAlgorithms: Collection<String>? = null,
    ): CredentialRequestProofContainer = CredentialRequestProofContainer(
        attestation = setOf(
            loadKeyAttestation.invoke(
                KeyAttestationInput(
                    credentialIssuer = credentialIssuer,
                    clientNonce = clientNonce,
                    supportedAlgorithms = supportedAlgorithms,
                    preferredKeyStorageStatusPeriod = keyAttestationRequired?.preferredTtl,
                    requirements = keyAttestationRequired
                )
            ).getOrThrow().jws
        )
    )

}