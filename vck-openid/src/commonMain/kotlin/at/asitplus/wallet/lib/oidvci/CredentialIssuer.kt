package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.BatchCredentialIssuanceMetadata
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.JwtVcIssuerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.decodeFromCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.toSupportedCredentialFormat
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Clock.System
import kotlin.coroutines.cancellation.CancellationException
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
    private val issuer: Issuer = IssuerAgent(),
    /** Key material used to sign credentials in [credential]. */
    private val keyMaterial: Set<KeyMaterial> = setOf(issuer.keyMaterial),
    /** Supported crypto algorithms of the key material used to sign credential in [credential]. */
    private val cryptoAlgorithms: Set<SignatureAlgorithm> = keyMaterial.map { it.signatureAlgorithm }.toSet(),
    /** List of supported credential schemes. */
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
    @Suppress("DEPRECATION") @Deprecated("Use `credentialDataProvider` in method `credential` instead")
    private val credentialProvider: CredentialIssuerDataProvider = FallbackCredentialIssuerDataProvider(),
    /** Used to verify the signature of proof elements in credential requests. */
    @Deprecated("Use `proofValidator` instead")
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    @Deprecated("Use `proofValidator` instead")
    private val supportedAlgorithms: Collection<JwsAlgorithm.Signature> = listOf(JwsAlgorithm.Signature.ES256),
    @Deprecated("Use `proofValidator` instead")
    private val clock: Clock = System,
    @Deprecated("Use `proofValidator` instead")
    private val timeLeeway: Duration = 5.minutes,
    @Deprecated("Use `proofValidator` instead")
    private val verifyAttestationProof: (JwsSigned<KeyAttestationJwt>) -> Boolean = { true },
    /** Turn on to require key attestation support in the [metadata]. */
    private val requireKeyAttestation: Boolean = false,
    @Deprecated("Use `proofValidator` instead")
    private val clientNonceService: NonceService = DefaultNonceService(),
    /** Used to optionally encrypt the credential response, if requested by the client. */
    private val encryptCredentialRequest: EncryptJweFun = EncryptJwe(EphemeralKeyWithoutCert()),
    /** Whether to indicate in [metadata] if credential response encryption is required. */
    private val requireEncryption: Boolean = false,
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweAlgorithms: Set<JweAlgorithm> = setOf(JweAlgorithm.ECDH_ES),
    /** Algorithms to indicate support for credential response encryption. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = setOf(JweEncryption.A256GCM),
    /** Used to verify proof of posession of key material in credential requests. */
    private val proofValidator: ProofValidator = ProofValidator(
        publicContext = publicContext,
        verifyJwsObject = verifyJwsObject,
        supportedAlgorithms = supportedAlgorithms,
        clock = clock,
        timeLeeway = timeLeeway,
        verifyAttestationProof = verifyAttestationProof,
        requireKeyAttestation = requireKeyAttestation,
        clientNonceService = clientNonceService,
    ),
) {
    private val supportedSigningAlgorithms = cryptoAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }.toSet()

    private val supportedCredentialConfigurations = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat().entries }
        .associate {
            it.key to it.value
                .withSupportedSigningAlgorithms(supportedSigningAlgorithms)
                .withSupportedProofTypes(proofValidator.validProofTypes())
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
                supportedEncryptionAlgorithmsStrings = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
                encryptionRequired = requireEncryption,
            )
        )
    }

    /**
     * Metadata about the credential issuer in
     * [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-jwt-vc-issuer-metadata)
     *
     * Issuers publishing JWT VC Issuer Metadata MUST make a JWT VC Issuer Metadata configuration available at the
     * location formed by inserting the well-known string `/.well-known/jwt-vc-issuer` (see
     * [OpenIdConstants.PATH_WELL_KNOWN_JWT_VC_ISSUER_METADATA]) between the host component and the path component (if
     * any) of the `iss` claim value in the JWT. The iss MUST be a case-sensitive URL using the HTTPS scheme that
     * contains scheme, host and, optionally, port number and path components, but no query or fragment components.
     */
    val jwtVcMetadata: JwtVcIssuerMetadata by lazy {
        JwtVcIssuerMetadata(
            issuer = publicContext,
            jsonWebKeySet = JsonWebKeySet(keyMaterial.map { it.jsonWebKey }.toSet())
        )
    }

    /**
     * Provides a fresh nonce to the clients, for incorporating them into the credential proofs.
     *
     * Requests from the client are HTTP POST.
     *
     * MUST be delivered with `Cache-Control: no-store` as HTTP header.
     */
    suspend fun nonce() = proofValidator.nonce()

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
    @Deprecated("Use `credential` with parameter `credentialDataProvider` instead")
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponseParameters> = credential(
        authorizationHeader = authorizationHeader,
        params = params,
        credentialDataProvider = CredentialIssuerDataProviderAdapter(credentialProvider),
        request = request,
    )

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
     * @param credentialDataProvider Extract data from the authenticated user and prepares it for issuing
     */
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters,
        credentialDataProvider: CredentialDataProviderFun,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponseParameters> = catching {
        proofValidator.validateProofExtractSubjectPublicKeys(params).map { subjectPublicKey ->
            issuer.issueCredential(
                credentialDataProvider(
                    with(params.extractCredentialRepresentation()) {
                        CredentialDataProviderInput(
                            userInfo = loadUserInfo(
                                authorizationHeader = authorizationHeader,
                                credentialIdentifier = params.credentialIdentifier,
                                credentialConfigurationId = params.credentialConfigurationId,
                                request = request
                            ),
                            subjectPublicKey = subjectPublicKey,
                            credentialScheme = first,
                            credentialRepresentation = second,
                        )
                    }
                ).getOrElse {
                    throw CredentialRequestDenied("No credential from provider", it)
                }
            ).getOrElse {
                throw CredentialRequestDenied("No credential from issuer", it)
            }
        }.toCredentialResponseParameters(params.encrypter())
            .also { Napier.i("credential returns $it") }
    }

    private fun CredentialRequestParameters.extractCredentialRepresentation()
            : Pair<CredentialScheme, ConstantIndex.CredentialRepresentation> =
        (credentialIdentifier?.let { decodeFromCredentialIdentifier(it) }
            ?: credentialConfigurationId?.let { extractFromCredentialConfigurationId(it) }
            ?: throw UnsupportedCredentialType("credential scheme not known from ${this}"))

    private fun extractFromCredentialConfigurationId(
        credentialConfigurationId: String,
    ): Pair<CredentialScheme, ConstantIndex.CredentialRepresentation>? =
        supportedCredentialConfigurations[credentialConfigurationId]?.let {
            decodeFromCredentialIdentifier(credentialConfigurationId)
        }

    @Throws(InvalidToken::class, CancellationException::class)
    private suspend fun loadUserInfo(
        authorizationHeader: String,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        request: RequestInfo? = null,
    ): OidcUserInfoExtended {
        val accessToken = authorizationService.tokenVerificationService
            .validateTokenExtractUser(authorizationHeader, request)
        if (credentialIdentifier != null) {
            if (accessToken.authorizationDetails == null)
                throw InvalidToken("no authorization details stored for header $authorizationHeader")
            if (!accessToken.validCredentialIdentifiers.contains(credentialIdentifier))
                throw InvalidToken("credential_identifier $credentialIdentifier expected to be in $accessToken")
        } else if (credentialConfigurationId != null) {
            if (accessToken.scope == null)
                throw InvalidToken("no scope stored for header $authorizationHeader")
            if (!accessToken.scope.contains(credentialConfigurationId))
                throw InvalidToken("credential_configuration_id $credentialConfigurationId expected to be $accessToken")
        } else {
            throw InvalidToken("neither credential_identifier nor credential_configuration_id set")
        }
        val userInfo = accessToken.userInfoExtended
            ?: throw InvalidToken("no user info stored for header $authorizationHeader")
        return userInfo
            .also { Napier.v("getUserInfo returns $it") }
    }

    /** Encrypts the issued credential, if requested so by the client. */
    private fun CredentialRequestParameters.encrypter(): (suspend (String) -> String) = { input: String ->
        credentialResponseEncryption?.let {
            it.jweEncryption?.let { jweEncryption ->
                encryptCredentialRequest(
                    header = JweHeader(
                        algorithm = it.jweAlgorithm,
                        encryption = jweEncryption,
                        keyId = it.jsonWebKey.keyId,
                    ),
                    payload = input,
                    recipientKey = it.jsonWebKey,
                ).getOrThrow().serialize()
            } ?: throw IllegalArgumentException("Unsupported encryption requested: ${it.jweEncryptionString}")
        } ?: input
    }

}

@Deprecated("Use `CredentialDataProviderFun` instead")
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

/** Fallback for deprecated constructor parameter, which should never be called, because when clients
 * migrate away from deprecated code, it's never used from our code,
 * when not, clients did set a correct implementation and that one is used. */
@Suppress("DEPRECATION")
private class FallbackCredentialIssuerDataProvider : CredentialIssuerDataProvider {
    override fun getCredential(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
    ): KmmResult<CredentialToBeIssued> = catching {
        TODO()
    }

}
