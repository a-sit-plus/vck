package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.KEY_ATTESTATION_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.PROOF_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.ProofType
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.CredentialRequestDenied
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidProof
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.UnsupportedCredentialType
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.datetime.Clock.System
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
 */
class CredentialIssuer(
    /** Used to get the user data, and access tokens. */
    private val authorizationService: OAuth2AuthorizationServerAdapter,
    /** Used to actually issue the credential. */
    private val issuer: Issuer,
    /** List of supported schemes. */
    private val credentialSchemes: Set<CredentialScheme>,
    /** Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients. */
    internal val publicContext: String = "https://wallet.a-sit.at/credential-issuer",
    /**
     * Used to build [IssuerMetadata.credentialEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [credential].
     */
    private val credentialEndpointPath: String = "/credential",
    /**
     * Used to build [IssuerMetadata.nonceEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [nonce].
     */
    private val nonceEndpointPath: String = "/nonce",
    /** Used during issuance, when issuing credentials (using [issuer]) with data from [OidcUserInfoExtended]. */
    private val credentialProvider: CredentialIssuerDataProvider,
    /** Used to verify signature of proof elements in credential requests. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    private val supportedAlgorithms: Collection<JwsAlgorithm.Signature> = listOf(JwsAlgorithm.Signature.ES256),
    /** Clock used to verify timestamps in proof elements in credential requests. */
    private val clock: Clock = System,
    /** Time leeway for verification of timestamps in proof elements in credential requests. */
    private val timeLeeway: Duration = 5.minutes,
    /** Callback to verify a received [KeyAttestationJwt] proof in credential requests. */
    private val verifyAttestationProof: (JwsSigned<KeyAttestationJwt>) -> Boolean = { true },
    /** Turn on to require key attestation support in the [metadata]. */
    private val requireKeyAttestation: Boolean = false,
    /** Used to provide challenge to clients to include in proof of possession of key material. */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /** Used to optionally encrypt the credential response, if requested by the client. */
    private val encryptCredentialRequest: EncryptJweFun = EncryptJwe(EphemeralKeyWithoutCert()),
    /** Whether to indicate in [metadata] if credential response encryption is required. */
    private val requireEncryption: Boolean = false,
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithms: Set<JweAlgorithm> = setOf(JweAlgorithm.ECDH_ES),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = setOf(JweEncryption.A256GCM),
) {
    private val supportedCredentialConfigurations = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat(issuer.cryptoAlgorithms).entries }
        .associate {
            it.key to if (requireKeyAttestation) {
                it.value.withSupportedProofTypes(
                    supportedProofTypes = mapOf(
                        ProofType.JWT.stringRepresentation to CredentialRequestProofSupported(
                            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
                            keyAttestationRequired = KeyAttestationRequired()
                        ),
                        ProofType.ATTESTATION.stringRepresentation to CredentialRequestProofSupported(
                            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
                            keyAttestationRequired = KeyAttestationRequired()
                        )
                    )
                )
            } else {
                it.value
            }
        }

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER])
     */
    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServers = setOf(authorizationService.publicContext),
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            nonceEndpointUrl = "$publicContext$nonceEndpointPath",
            supportedCredentialConfigurations = supportedCredentialConfigurations,
            batchCredentialIssuance = BatchCredentialIssuanceMetadata(1),
            credentialResponseEncryption = SupportedAlgorithmsContainer(
                supportedAlgorithmsStrings = supportedJweAlgorithms.map { it.identifier }.toSet(),
                supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.text }.toSet(),
                encryptionRequired = requireEncryption,
            )
        )
    }

    /**
     * Serve this result JSON-serialized under `/.well-known/jwt-vc-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_JWT_VC_ISSUER_METADATA]),
     * so that verifiers can look up the keys used to sign credentials.
     */
    val jwtVcMetadata: JwtVcIssuerMetadata by lazy {
        JwtVcIssuerMetadata(
            issuer = publicContext,
            jsonWebKeySet = JsonWebKeySet(setOf(issuer.keyMaterial.jsonWebKey))
        )
    }

    /**
     * Provides a fresh nonce to the clients, for incorporating them into the credential proofs.
     *
     * Requests from the client are HTTP POST.
     *
     * MUST be delivered with `Cache-Control: no-store` as HTTP header.
     */
    suspend fun nonce() = catching {
        ClientNonceResponse(
            clientNonce = clientNonceService.provideNonce()
        )
    }

    /**
     * Verifies the [authorizationHeader] to contain a token from [authorizationService],
     * verifies the proof sent by the client (must contain a nonce sent from [authorizationService]),
     * and issues credentials to the client.
     *
     * Callers need to send the result JSON-serialized back to the client.
     * HTTP status code MUST be 202.
     *
     * @param authorizationHeader value of HTTP header `Authorization` sent by the client, with all prefixes
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     * @param request information about the HTTP request the client has made, to validate authentication
     */
    @Suppress("DEPRECATION")
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponseParameters> = catching {
        val userInfo =
            getUserInfo(authorizationHeader, params.credentialIdentifier, params.credentialConfigurationId, request)

        val (credentialScheme, representation) = params.credentialIdentifier?.let { decodeFromCredentialIdentifier(it) }
            ?: params.credentialConfigurationId?.let { extractFromCredentialConfigurationId(it) }
            ?: throw UnsupportedCredentialType("credential scheme not known")
                .also { Napier.w("credential: client did request unknown credential scheme: $params") }

        val issuedCredentials = validateProofExtractSubjectPublicKeys(params).map { subjectPublicKey ->
            val credentialToBeIssued = credentialProvider.getCredential(
                userInfo = userInfo,
                subjectPublicKey = subjectPublicKey,
                credentialScheme = credentialScheme,
                representation = representation.toRepresentation(),
                claimNames = null // OID4VCI: Always issue all claims that are available
            ).getOrElse {
                throw CredentialRequestDenied("No credential from provider", it)
                    .also { Napier.w("credential: did not get any credential from credentialProvider", it) }
            }
            issuer.issueCredential(
                credential = credentialToBeIssued
            ).getOrElse {
                throw CredentialRequestDenied("No credential from issuer", it)
                    .also { Napier.w("credential: issuer did not issue credential", it) }
            }
        }
        issuedCredentials.toCredentialResponseParameters(params.encrypter())
            .also { Napier.i("credential returns $it") }
    }

    private suspend fun getUserInfo(
        authorizationHeader: String,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        request: RequestInfo? = null,
    ): OidcUserInfoExtended {
        val result = authorizationService.tokenVerificationService
            .validateTokenExtractUser(authorizationHeader, request)

        if (credentialIdentifier != null) {
            if (result.authorizationDetails == null)
                throw InvalidToken("no authorization details stored for header $authorizationHeader")
            val validCredentialIdentifiers = result.authorizationDetails
                .filterIsInstance<OpenIdAuthorizationDetails>()
                .flatMap { it.credentialIdentifiers ?: setOf() }
            if (!validCredentialIdentifiers.contains(credentialIdentifier))
                throw InvalidToken("credential_identifier expected to be in ${validCredentialIdentifiers}, but got $credentialIdentifier")
        } else if (credentialConfigurationId != null) {
            if (result.scope == null)
                throw InvalidToken("no scope stored for header $authorizationHeader")
            if (!result.scope.contains(credentialConfigurationId))
                throw InvalidToken("credential_configuration_id expected to be ${result.scope}, but got $credentialConfigurationId")
        } else {
            throw InvalidToken("neither credential_identifier nor credential_configuration_id set")
        }

        return result.userInfoExtended!!
            .also { Napier.v("getUserInfo returns $it") }
    }

    /** Encrypts the issued credential, if requested so by the client. */
    private fun CredentialRequestParameters.encrypter(): (suspend (String) -> String) = { it: String ->
        if (credentialResponseEncryption?.jweEncryption != null) {
            with(credentialResponseEncryption!!) {
                encryptCredentialRequest(
                    JweHeader(
                        algorithm = jweAlgorithm,
                        encryption = jweEncryption,
                        keyId = jsonWebKey.keyId,
                    ),
                    it,
                    jsonWebKey,
                ).getOrNull()?.serialize() ?: it
            }
        } else {
            it
        }
    }

    private suspend fun validateProofExtractSubjectPublicKeys(params: CredentialRequestParameters): Collection<CryptoPublicKey> =
        params.proof?.validateProof()
            ?: params.proofs?.validateProof()
            ?: throw InvalidRequest("invalid proof")
                .also { Napier.w("credential: client did not provide proof of possession in $params") }

    private suspend fun CredentialRequestProof.validateProof() = when (proofType) {
        ProofType.JWT -> jwtParsed?.validateJwtProof()
        ProofType.ATTESTATION -> attestationParsed?.validateAttestationProof()
        else -> null
    }

    private suspend fun CredentialRequestProofContainer.validateProof() = when (proofType) {
        ProofType.JWT -> jwtParsed?.flatMap { it.validateJwtProof() }
        ProofType.ATTESTATION -> attestationParsed?.flatMap { it.validateAttestationProof() }
        else -> jwtParsed?.flatMap { it.validateJwtProof() }
            ?: attestationParsed?.flatMap { it.validateAttestationProof() }
    }

    private suspend fun JwsSigned<JsonWebToken>.validateJwtProof(): Collection<CryptoPublicKey> {
        if (header.type != PROOF_JWT_TYPE) {
            Napier.w("validateJwtProof: invalid typ: $header")
            throw InvalidProof("invalid typ: ${header.type}")
        }

        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            Napier.w("validateJwtProof: invalid nonce: ${payload.nonce}")
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }

        if (payload.audience == null || payload.audience != publicContext) {
            Napier.w("validateJwtProof: invalid audience: ${payload.audience}")
            throw InvalidProof("invalid audience: ${payload.audience}")
        }

        if (!verifyJwsObject(this)) {
            Napier.w("validateJwtProof: invalid signature: $this")
            throw InvalidProof("invalid signature: $this")
        }
        // OID4VCI 8.2.1.1: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
        // in the attested_keys claim within the key_attestation parameter.
        val additionalKeys = header.keyAttestationParsed?.validateAttestationProof() ?: listOf()

        val headerPublicKey = header.publicKey ?: run {
            Napier.w("validateJwtProof: No valid key in header: $header")
            throw InvalidProof("could not extract public key")
        }

        return additionalKeys + headerPublicKey
    }

    /**
     * OID4VCI 8.2.1.3: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
     * in the `attested_keys` claim.
     */
    private suspend fun JwsSigned<KeyAttestationJwt>.validateAttestationProof(): Collection<CryptoPublicKey> {
        if (header.type != KEY_ATTESTATION_JWT_TYPE) {
            Napier.w("validateAttestationProof: invalid typ: $header")
            throw InvalidProof("invalid typ: ${header.type}")
        }
        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            Napier.w("validateAttestationProof: invalid nonce: ${payload.nonce}")
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        if (payload.issuedAt > (clock.now() + timeLeeway)) {
            Napier.w("validateAttestationProof: issuedAt in future: ${payload.issuedAt}")
            throw InvalidProof("issuedAt in future: ${payload.issuedAt}")
        }

        if (payload.expiration != null && payload.expiration!! < (clock.now() - timeLeeway)) {
            Napier.w("validateAttestationProof: expiration in past: ${payload.expiration}")
            throw InvalidProof("expiration in past: ${payload.expiration}")
        }

        if (!verifyAttestationProof.invoke(this)) {
            Napier.w("validateAttestationProof: Key attestation not verified by callback: $this")
            throw InvalidProof("key attestation not verified: $this")
        }
        return payload.attestedKeys.mapNotNull {
            it.toCryptoPublicKey()
                .onFailure { Napier.w("validateAttestationProof: Could not convert to public key", it) }
                .getOrNull()
        }
    }

    private fun extractFromCredentialConfigurationId(credentialConfigurationId: String): Pair<CredentialScheme, CredentialFormatEnum>? =
        supportedCredentialConfigurations[credentialConfigurationId]?.let {
            decodeFromCredentialIdentifier(credentialConfigurationId)
        }
}

fun interface CredentialIssuerDataProvider {

    /**
     * Gets called with the user authorized in [userInfo],
     * a resolved [credentialScheme],
     * the holder key in [subjectPublicKey],
     * and the requested credential [representation].
     * Callers may optionally define some attribute names from [ConstantIndex.CredentialScheme.claimNames] in
     * [claimNames] to request only some claims (if supported by the representation).
     */
    fun getCredential(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
    ): KmmResult<CredentialToBeIssued>
}
