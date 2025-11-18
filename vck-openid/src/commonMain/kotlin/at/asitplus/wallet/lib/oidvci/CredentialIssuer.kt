package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.BatchCredentialIssuanceMetadata
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.JwtVcIssuerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.decodeFromCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.toSupportedCredentialFormat
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class CredentialIssuer(
    /** Used to get the user data, and access tokens. */
    private val authorizationService: OAuth2AuthorizationServerAdapter,
    /** Used to actually issue the credential. */
    private val issuer: Issuer,
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
     * to that URI (which starts with [publicContext]) to [nonceWithDpopNonce].
     */
    private val nonceEndpointPath: String = "/nonce",
    /** Turn on to require key attestation support in the [metadata]. */
    private val requireKeyAttestation: Boolean = false,
    /** Used to verify proof of posession of key material in credential requests. */
    private val proofValidator: ProofValidator = ProofValidator(
        publicContext = publicContext,
        requireKeyAttestation = requireKeyAttestation,
    ),
    /** Used to provide signed metadata in [signedMetadata]. */
    private val signMetadata: SignJwtFun<IssuerMetadata> = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()),
    /** Handles credential request decryption and credential response encryption. */
    private val encryptionService: IssuerEncryptionService = IssuerEncryptionService(),
) {

    sealed interface CredentialResponse {
        /**
         * Send [response] as JSON-serialized content to the client with media
         * type `application/json` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JSON]).
         */
        data class Plain(val response: CredentialResponseParameters) : CredentialResponse

        /**
         * Send [response] as JWE-serialized content to the client with media
         * type `application/jwt` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JWT]).
         */
        data class Encrypted(val response: JweEncrypted) : CredentialResponse
    }

    private val supportedCredentialConfigurations = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat().entries }
        .associate {
            it.key to it.value
                .withSupportedSigningAlgorithms(cryptoAlgorithms.toSet())
                .withSupportedProofTypes(proofValidator.validProofTypes())
        }

    /**
     * MUST be delivered with HTTP header `Cache-Control: no-store` (see [io.ktor.http.HttpHeaders.CacheControl]).
     * Include [response] as the JSON-serialized body, and [dpopNonce] in HTTP header `DPoP-Nonce` when present.
     */
    data class Nonce(
        val response: ClientNonceResponse,
        val dpopNonce: String? = null,
    )

    /**
     * Serve this result serialized at the path formed by inserting the string `/.well-known/openid-credential-issuer`
     * (see [OpenIdConstants.WellKnownPaths.CredentialIssuer]) into the Credential Issuer Identifier between the host
     * component and the path component, if any.
     * Use `application/json` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JSON]) as the `Content-Type`
     * header (see [io.ktor.http.HttpHeaders.ContentType]) in the response.
     * See also [signedMetadata].
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
            credentialResponseEncryption = encryptionService.metadataCredentialResponseEncryption,
            credentialRequestEncryption = encryptionService.metadataCredentialRequestEncryption,
        )
    }

    /**
     * Serve this result serialized at the path formed by inserting the string `/.well-known/openid-credential-issuer`
     * (see [OpenIdConstants.WellKnownPaths.CredentialIssuer]) into the Credential Issuer Identifier between the host
     * component and the path component, if any.
     * Use this only when the client accepts (see `Accept` header [io.ktor.http.HttpHeaders.Accept]) the media type
     * `application/jwt` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JWT]), otherwise serve [metadata].
     */
    suspend fun signedMetadata(): KmmResult<JwsSigned<IssuerMetadata>> =
        signMetadata(null, metadata, IssuerMetadata.serializer())

    /**
     * Metadata about the credential issuer in
     * [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-jwt-vc-issuer-metadata)
     *
     * Issuers publishing JWT VC Issuer Metadata MUST make a JWT VC Issuer Metadata configuration available at the
     * location formed by inserting the well-known string `/.well-known/jwt-vc-issuer` (see
     * [OpenIdConstants.WellKnownPaths.JwtVcIssuer]) between the host component and the path component (if
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
     * Provides a fresh nonce for credential proofs and a DPoP nonce for DPoP proofs.
     * Requests from the client are HTTP POST.
     */
    suspend fun nonceWithDpopNonce(): KmmResult<Nonce> = catching {
        Nonce(proofValidator.nonce(), authorizationService.getDpopNonce())
    }

    @Deprecated("Use [credential] with [WalletService.CredentialRequest] instead")
    suspend fun credentialEncryptedRequest(
        authorizationHeader: String,
        input: String,
        credentialDataProvider: CredentialDataProviderFun,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponseParameters> = catching {
        credentialInternal(
            authorizationHeader = authorizationHeader,
            request = encryptionService.decrypt(input).getOrThrow(),
            credentialDataProvider = credentialDataProvider,
            requestInfo = request,
            hasBeenEncrypted = true,
        ).getOrThrow().toCredentialResponseParameters()
    }

    private fun CredentialResponse.toCredentialResponseParameters() = when (this) {
        is CredentialResponse.Encrypted -> TODO()
        is CredentialResponse.Plain -> response
    }

    @Deprecated("Use [credential] with [WalletService.CredentialRequest] instead")
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters,
        credentialDataProvider: CredentialDataProviderFun,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponseParameters> = catching {
        credentialInternal(
            authorizationHeader = authorizationHeader,
            request = params,
            credentialDataProvider = credentialDataProvider,
            requestInfo = request,
            hasBeenEncrypted = false,
        ).getOrThrow().toCredentialResponseParameters()
    }

    /**
     * Verifies the [authorizationHeader] to contain a token from [authorizationService],
     * verifies the proof sent by the client (must contain a nonce sent from [authorizationService]),
     * and issues credentials to the client by calling [credentialDataProvider].
     *
     * Callers need to send the result as HTTP status code 200 back to the client, see [CredentialResponse].
     *
     * @param authorizationHeader value of HTTP header `Authorization` sent by the client, with all prefixes
     * @param params Parameters the client sent in the HTTP body, either JSON serialized or as a string,
     * see [WalletService.CredentialRequest.parse]
     * @param credentialDataProvider Extract data from the authenticated user and prepares it for issuing
     * @param request information about the HTTP request the client has made, to validate authentication
     *
     * @return If the result is an instance of [OAuth2Exception] send [OAuth2Exception.toOAuth2Error] back to the
     * client, except for instances of [OAuthAuthorizationError]
     */
    suspend fun credential(
        authorizationHeader: String,
        params: WalletService.CredentialRequest,
        credentialDataProvider: CredentialDataProviderFun,
        request: RequestInfo? = null,
    ): KmmResult<CredentialResponse> = catching {
        credentialInternal(
            authorizationHeader = authorizationHeader,
            request = params.decryptIfNeeded(),
            credentialDataProvider = credentialDataProvider,
            requestInfo = request,
            hasBeenEncrypted = params is WalletService.CredentialRequest.Encrypted,
        ).getOrThrow()
    }

    private suspend fun WalletService.CredentialRequest.decryptIfNeeded() = when (this) {
        is WalletService.CredentialRequest.Encrypted -> encryptionService.decrypt(request.serialize()).getOrThrow()
        is WalletService.CredentialRequest.Plain -> request
    }

    private suspend fun credentialInternal(
        authorizationHeader: String,
        request: CredentialRequestParameters,
        credentialDataProvider: CredentialDataProviderFun,
        requestInfo: RequestInfo? = null,
        hasBeenEncrypted: Boolean = false,
    ): KmmResult<CredentialResponse> = catching {
        Napier.i("credential called")
        Napier.d("credential called with $authorizationHeader, $request")
        if (!hasBeenEncrypted && encryptionService.requireRequestEncryption)
            throw InvalidEncryptionParameters("Credential request has not been encrypted")
        authorizationService.validateAccessToken(authorizationHeader, requestInfo).getOrThrow()
        val userInfo = request.introspectTokenLoadUserInfo(authorizationHeader, requestInfo)
        val (scheme, representation) = request.extractCredentialRepresentation()
        val responseParameters = proofValidator.validateProofExtractSubjectPublicKeys(request).map { subjectPublicKey ->
            // TODO into one array?
            issuer.issueCredential(
                credentialDataProvider(
                    CredentialDataProviderInput(
                        userInfo = userInfo,
                        subjectPublicKey = subjectPublicKey,
                        credentialScheme = scheme,
                        credentialRepresentation = representation,
                    )
                ).getOrElse {
                    throw CredentialRequestDenied("No credential from provider", it)
                }
            ).getOrElse {
                throw CredentialRequestDenied("No credential from issuer", it)
            }
        }.toCredentialResponseParameters()
        encryptionService.encryptResponse(responseParameters, request)
            .also { Napier.i("credential returns"); Napier.d("credential returns $it") }
    }

    private suspend fun CredentialRequestParameters.introspectTokenLoadUserInfo(
        authorizationHeader: String,
        request: RequestInfo?,
    ): OidcUserInfoExtended = run {
        validateAgainstToken(authorizationHeader, request)
        authorizationService.getUserInfo(
            authorizationHeader = authorizationHeader,
            httpRequest = request
        ).getOrThrow().let {
            OidcUserInfoExtended.fromJsonObject(it).getOrThrow()
        }
    }

    private suspend fun CredentialRequestParameters.validateAgainstToken(
        authorizationHeader: String,
        request: RequestInfo?,
    ): Unit = authorizationService.getTokenInfo(
        authorizationHeader = authorizationHeader,
        httpRequest = request,
    ).getOrThrow().let {
        if (it.authorizationDetails != null) {
            if (credentialIdentifier == null)
                throw InvalidCredentialRequest("credential_identifier expected to be set")
            if (credentialConfigurationId != null)
                throw InvalidCredentialRequest("credential_configuration_id must not be set when credential_identifier is set")
            if (!it.validCredentialIdentifiers.contains(credentialIdentifier))
                throw InvalidToken("credential_identifier $credentialIdentifier expected to be in $it")
        } else if (it.scope != null) {
            if (credentialConfigurationId == null)
                throw InvalidCredentialRequest("credential_configuration_id expected to be set")
            if (credentialIdentifier != null)
                throw InvalidCredentialRequest("credential_identifier must not be set when credential_configuration_id is set")
            if (!it.scope.contains(credentialConfigurationId!!))
                throw InvalidToken("credential_configuration_id $credentialConfigurationId expected to be in $it")
        } else {
            throw InvalidToken("Neither scope nor authorization details stored for access token")
        }
    }


    private fun CredentialRequestParameters.extractCredentialRepresentation()
            : Pair<CredentialScheme, ConstantIndex.CredentialRepresentation> =
        credentialIdentifier?.let {
            decodeFromCredentialIdentifier(it)
                ?: throw UnknownCredentialIdentifier(it)
        } ?: credentialConfigurationId?.let {
            extractFromCredentialConfigurationId(it)
                ?: throw UnknownCredentialConfiguration(it)
        } ?: throw InvalidCredentialRequest("Neither credential_identifier nor credential_configuration_id set")

    private fun extractFromCredentialConfigurationId(
        credentialConfigurationId: String,
    ): Pair<CredentialScheme, ConstantIndex.CredentialRepresentation>? =
        supportedCredentialConfigurations[credentialConfigurationId]?.let {
            decodeFromCredentialIdentifier(credentialConfigurationId)
        }

}

