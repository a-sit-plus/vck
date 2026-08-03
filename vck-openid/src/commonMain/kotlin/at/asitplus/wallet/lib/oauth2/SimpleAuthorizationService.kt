package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.sha256
import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferGrants
import at.asitplus.openid.CredentialOfferGrantsAuthCode
import at.asitplus.openid.CredentialOfferGrantsPreAuthCode
import at.asitplus.openid.CredentialOfferGrantsPreAuthCodeTransactionCode
import at.asitplus.openid.CredentialOfferUrlParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.openid.TokenIntrospectionRequestContent
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenIntrospectionResponseJson
import at.asitplus.openid.TokenIntrospectionResponseJwt
import at.asitplus.openid.TokenIntrospectionResponseJwtPayload
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IntrospectionJwt
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.CodeService
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.DefaultCodeService
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFun
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFunInput
import at.asitplus.wallet.lib.oidvci.TokenInfo
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.RequestParser
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * with the actual authentication and authorization logic for credential schemes implemented in [strategy].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 * Also implements necessary parts of
 * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
 * , Draft 03, 2025-02-07, e.g.
 * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126),
 * [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636),
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449),
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 * [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
 * [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
 */
class SimpleAuthorizationService @JvmOverloads constructor(
    /** Used to filter authorization details and scopes. */
    private val strategy: AuthorizationServiceStrategy,
    /** Used to load the actual user data during [authorize]. */
    /** Used to create and verify authorization codes issued by [authorize]. */
    private val codeService: CodeService = DefaultCodeService(),
    /** Used in several fields in [OAuth2AuthorizationServerMetadata], to provide endpoint URLs to clients. */
    override val publicContext: String = "https://wallet.a-sit.at/authorization-server",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.authorizationEndpoint], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [authorize].
     */
    private val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.tokenEndpoint], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    private val tokenEndpointPath: String = "/token",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.pushedAuthorizationRequestEndpoint], i.e. implementers need to
     * forward POST requests to that URI (which starts with [publicContext]) to [par].
     */
    private val pushedAuthorizationRequestEndpointPath: String = "/par",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.userInfoEndpoint], i.e. implementers need to forward POST or GET
     * requests to that URI (which starts with [publicContext]) to [userInfo].
     */
    private val userInfoEndpointPath: String = "/userinfo",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.introspectionEndpoint], i.e. implementers need to forward POST or GET
     * requests to that URI (which starts with [publicContext]) to [getTokenInfo].
     */
    private val introspectionEndpointPath: String = "/introspect",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.challengeEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [attestationChallenge].
     */
    private val challengeEndpointPath: String = "/challenge",
    /** Associates issuer_state with credential offers. */
    private val issuerStateToCredentialOffer: MapStore<String, CredentialOffer> = DefaultMapStore(),
    /** Associates issued codes with the auth request from the client. */
    private val codeToClientAuthRequest: MapStore<String, ClientAuthRequest> = DefaultMapStore(),
    /** Associates issued refresh tokens with the auth request from the client. *Refresh tokens are usually long-lived!* */
    private val refreshTokenToAuthRequest: MapStore<String, ClientAuthRequest> =
        DefaultMapStore(lifetime = 30.days),
    /** Associates the issued `request_uri` sent to the client to the actual request from the client. */
    private val requestUriToPushedAuthorizationRequest: MapStore<String, PushedAuthorizationRequest> = DefaultMapStore(),
    /** Service to create and validate access tokens. */
    private val tokenService: TokenService = TokenService.bearer(),
    /** Handles client authentication in [par] and [token]. Defaults to [NoopClientAuthenticationService]! */
    private val clientAuthenticationService: ClientAuthenticationService = NoopClientAuthenticationService,
    /** Used to parse requests from clients, e.g., when using JWT-Secured Authorization Requests (RFC 9101) */
    private val requestParser: RequestParser = RequestParser(
        /** By default, do not retrieve authn requests referenced by `request_uri`. */
        remoteResourceRetriever = { null },
        /** Not necessary to load the authn request referenced by `request_uri`. */
        buildRequestObjectParameters = { null }
    ),
    /** Must be set to `true` for OID4VC HAIP, advertised in [metadata]. */
    private val requirePushedAuthorizationRequests: Boolean = true,
    /**
     * Sets [OAuth2AuthorizationServerMetadata.requestObjectSigningAlgorithmsSupported].
     * Currently, we only support [JwsAlgorithm.Signature.ES256].
     * If set the client MAY wrap [RequestParameters] as [JarRequestParameters]
     * - this is the default behavior of `OAuth2KtorClient`
     */
    private val requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>? = setOf(JwsAlgorithm.Signature.ES256),
    /** Used for [OAuth2AuthorizationServerMetadata.clientAttestationSigningAlgValuesSupportedStrings] */
    private val supportedSigningAlgorithms: Set<JwsAlgorithm.Signature> = DEFAULT_WALLET_ATTESTATION_ALGORITHMS,
    /** Used to sign JWT introspection responses (RFC 9701). */
    private val signIntrospectionJwt: SignJwtFun<TokenIntrospectionResponseJwtPayload> =
        SignJwt(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()),
    /** Used to create and verify `issuer_state` values of credential offers. */
    private val issuerStateService: CodeService = DefaultCodeService(),
    /** Used to create and verify pre-authorized codes, see [providePreAuthorizedCode]. */
    private val preAuthorizedCodeService: CodeService = DefaultCodeService(),
    /**
     * Whether to support Token Exchange, i.e. issuing a fresh access token for a token presented as `subject_token`.
     * Requires [tokenService] with support for it.
     */
    private val supportTokenExchange: Boolean = false,
) : OAuth2AuthorizationServerAdapter, AuthorizationService {

    init {
        if (clientAuthenticationService.supportedAuthMethods.orEmpty()
                .contains(OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP)
            && tokenService.dpopSigningAlgValuesSupportedStrings.orEmpty().isEmpty()
        ) {
            throw IllegalArgumentException("Client authn DPoP combined mode requires Token Service with DPoP support")
        }
        if (supportTokenExchange && !tokenService.supportsTokenExchange) {
            throw IllegalArgumentException(
                "Token exchange requires a Token Service that binds the subject token to the presenting client"
            )
        }
    }

    companion object {
        val DEFAULT_WALLET_ATTESTATION_ALGORITHMS: Set<JwsAlgorithm.Signature> = setOf(
            JwsAlgorithm.Signature.ES256,
            JwsAlgorithm.Signature.ES384,
            JwsAlgorithm.Signature.ES512,
        )
    }

    private val _metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
            pushedAuthorizationRequestEndpoint = "$publicContext$pushedAuthorizationRequestEndpointPath",
            userInfoEndpoint = "$publicContext$userInfoEndpointPath",
            introspectionEndpoint = "$publicContext$introspectionEndpointPath",
            challengeEndpoint = clientAuthenticationService.supportedAuthMethods.takeIf { it != null }
                ?.let { "$publicContext$challengeEndpointPath" },
            requirePushedAuthorizationRequests = requirePushedAuthorizationRequests,
            codeChallengeMethodsSupported = setOf(OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256),
            introspectionEndpointAuthMethodsSupported = clientAuthenticationService.supportedAuthMethods,
            tokenEndPointAuthMethodsSupported = clientAuthenticationService.supportedAuthMethods,
            clientAttestationSigningAlgValuesSupportedStrings = clientAuthenticationService.supportedSigningAlgs,
            clientAttestationPopSigningAlgValuesSupportedStrings = clientAuthenticationService.supportedPopSigningAlgs,
            clientAttestationPopMethodsSupported = clientAuthenticationService.supportedPopMethods,
            dpopSigningAlgValuesSupportedStrings = tokenService.dpopSigningAlgValuesSupportedStrings,
            requestObjectSigningAlgorithmsSupportedStrings = requestObjectSigningAlgorithms
                ?.map { it.identifier }?.toSet(),
            grantTypesSupported = setOfNotNull(
                OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE,
                OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE,
                if (supportTokenExchange) OpenIdConstants.GRANT_TYPE_TOKEN_EXCHANGE else null,
                if (tokenService.supportsRefreshTokens) OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN else null,
            )
        )
    }

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.WellKnownPaths.OpenidConfiguration],
     * and under `/.well-known/oauth-authorization-server`,
     * see [OpenIdConstants.WellKnownPaths.OauthAuthorizationServer].
     */
    override suspend fun metadata(): OAuth2AuthorizationServerMetadata = _metadata

    /**
     * MUST be delivered with HTTP header `Cache-Control: no-store` (see [io.ktor.http.HttpHeaders.CacheControl]).
     * Serialize the body as JSON.
     * See
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#name-challenges)
     */
    suspend fun attestationChallenge(): KmmResult<AttestationChallengeResponse?> = catching {
        clientAuthenticationService.getAttestationChallenge()?.let {
            AttestationChallengeResponse(attestationChallenge = it)
        }
    }

    /**
     * Offer some credential identifiers from [strategy] to clients with auth-code flow.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param credentialIssuer the public context of an [CredentialIssuer]
     * @param schemes which credential configuration IDs to use in the offer.
     * Pass an empty set to offer all known schemes.
     */
    suspend fun offerWithAuthorizationCodeForSchemes(
        credentialIssuer: String,
        schemes: Set<Pair<CredentialScheme, CredentialRepresentation>> = emptySet(),
    ): CredentialOffer = buildOfferWithAuthorizationCode(
        credentialIssuer = credentialIssuer,
        configurationIds = strategy.toCredentialConfigurationIds(schemes),
    )

    private suspend fun buildOfferWithAuthorizationCode(
        credentialIssuer: String,
        configurationIds: Collection<String>,
    ): CredentialOffer = issuerStateService.provideCode().let { issuerState ->
        CredentialOffer(
            credentialIssuer = credentialIssuer,
            configurationIds = configurationIds.toSet(),
            grants = CredentialOfferGrants(
                authorizationCode = CredentialOfferGrantsAuthCode(
                    issuerState = issuerState,
                    authorizationServer = publicContext
                ),
            )
        ).also {
            issuerStateToCredentialOffer.put(issuerState, it)
        }
    }

    /**
     * Offer all available schemes from [strategy] to clients.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param user used to create the credential when the wallet app requests the credential
     * @param credentialIssuer the public context of an [CredentialIssuer]
     * @param schemes which credential configuration IDs to use in the offer.
     * Pass an empty set to offer all known schemes.
     * @param transactionCode OID4VCI transaction code the user has to enter in the wallet app, to be transmitted to
     * them out-of-band. Recommended, since anyone who reads the offer (e.g. by photographing the QR code) can
     * otherwise redeem the pre-authorized code.
     * @param transactionCodeDescriptor describes [transactionCode] to the wallet app, so it can render an input screen
     */
    suspend fun offerWithPreAuthnForUserForSchemes(
        user: OidcUserInfoExtended,
        credentialIssuer: String,
        schemes: Set<Pair<CredentialScheme, CredentialRepresentation>> = emptySet(),
        transactionCode: String? = null,
        transactionCodeDescriptor: CredentialOfferGrantsPreAuthCodeTransactionCode? =
            transactionCode?.let { CredentialOfferGrantsPreAuthCodeTransactionCode(length = it.length) },
    ): CredentialOffer {
        require((transactionCode == null) == (transactionCodeDescriptor == null)) {
            "transactionCode and transactionCodeDescriptor must either both be set or both be null"
        }
        return buildOfferWithPreAuthnForUser(
            user = user,
            credentialIssuer = credentialIssuer,
            configurationIds = strategy.toCredentialConfigurationIds(schemes),
            transactionCode = transactionCode,
            transactionCodeDescriptor = transactionCodeDescriptor,
        )
    }

    private suspend fun buildOfferWithPreAuthnForUser(
        user: OidcUserInfoExtended,
        credentialIssuer: String,
        configurationIds: Collection<String>,
        transactionCode: String? = null,
        transactionCodeDescriptor: CredentialOfferGrantsPreAuthCodeTransactionCode? = null,
    ): CredentialOffer = CredentialOffer(
        credentialIssuer = credentialIssuer,
        configurationIds = configurationIds.toSet(),
        grants = CredentialOfferGrants(
            preAuthorizedCode = CredentialOfferGrantsPreAuthCode(
                preAuthorizedCode = providePreAuthorizedCode(
                    userInfo = user,
                    configurationIds = configurationIds.toSet(),
                    transactionCode = transactionCode,
                ),
                transactionCode = transactionCodeDescriptor,
                authorizationServer = publicContext
            )
        )
    )

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param input as sent from the client as `POST` body
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun par(
        input: String,
        httpRequest: RequestInfo?,
    ) = par(
        request = requestParser.parseRequestParameters(input).getOrThrow().parameters,
        httpRequest = httpRequest
    )

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun par(
        request: RequestParameters,
        httpRequest: RequestInfo?,
    ) = catching {
        val actualRequest = request.extractPushedRequestParams()
        Napier.i("par called with $actualRequest")
        val validatedClientKey = httpRequest?.validatedClientKey()
        val presentedClient = clientAuthenticationService.authenticateClient(
            httpRequest = httpRequest,
            clientId = actualRequest.clientId,
            validatedClientKey = validatedClientKey
        ).getOrThrow()
            ?: throw InvalidRequest("client could not be authenticated")
        // PAR stores the request for later authorization. issuer_state is single-use and must only be consumed
        // when /authorize is executed with the referenced request_uri.
        val validatedRequest = actualRequest.validate(validateIssuerState = false)
        val requestUri = "urn:ietf:params:oauth:request_uri:${uuid4()}".also {
            requestUriToPushedAuthorizationRequest.put(
                it,
                PushedAuthorizationRequest(validatedRequest, presentedClient)
            )
        }
        PushedAuthenticationResponseParameters(
            requestUri = requestUri,
            expires = 5.minutes,
        )
    }

    /**
     * Like [par], but also provides a fresh DPoP nonce for the success response header.
     * See [RFC 9449 8. Authorization Server-Provided Nonce](https://datatracker.ietf.org/doc/html/rfc9449#section-8)
     */
    suspend fun parWithDpopNonce(
        request: RequestParameters,
        httpRequest: RequestInfo? = null,
    ): KmmResult<ResponseWithDpopNonce<PushedAuthenticationResponseParameters>> = catching {
        val response = par(request, httpRequest).getOrThrow()
        ResponseWithDpopNonce(response, tokenService.dpopNonce())
    }

    private suspend fun RequestParameters.extractPushedRequestParams() = when (this) {
        is JarRequestParameters -> {
            require(requestUri == null) { "request_uri must not be set for PAR" }
            requestParser.extractRequest(this, null)?.parameters as? AuthenticationRequestParameters
                ?: throw InvalidRequest("request must contain valid authorization request parameters")
        }

        is AuthenticationRequestParameters -> this
        else -> throw InvalidRequest("Request is neither plain nor JAR")
    }

    /**
     * Builds the authentication response for this specific user from [loadUserFun].
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL built from client's `redirect_uri` with `code` parameter, [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun authorize(
        input: RequestParameters,
        loadUserFun: OAuth2LoadUserFun,
    ) = catching {
        val (actualRequest, authenticatedClient) = extractRequestForAuthorize(input)
            .let { it.first.validate() to it.second }
        val userInfo = loadUserFun(OAuth2LoadUserFunInput(actualRequest)).getOrElse {
            throw InvalidRequest("Could not load user info for request $input", it)
        }
        with(actualRequest) {
            issueCodeForUserInfo(userInfo, actualRequest, authenticatedClient)
                .also { Napier.i("authorize returns $it") }
        }
    }

    internal suspend fun issueCodeForUserInfo(
        userInfo: OidcUserInfoExtended,
        request: AuthenticationRequestParameters,
        clientBinding: ClientBinding?,
    ): AuthenticationResponseResult.Redirect {
        // Client authentication in par() already validated its client_id against the authenticated one,
        // and extractRequestForAuthorize() compares the stored request against the one from /authorize.
        val boundClient = clientBinding
            ?: request.clientId?.let(::UnauthenticatedClient)
            ?: throw InvalidRequest("client_id not set")
        val response = AuthenticationResponseParameters(
            code = codeService.provideCode().also { code ->
                codeToClientAuthRequest.put(
                    code,
                    ClientAuthRequest(
                        issuedCode = code,
                        userInfo = userInfo,
                        scope = request.scope,
                        authnDetails = request.authorizationDetails,
                        codeChallenge = request.codeChallenge,
                        clientBinding = boundClient,
                    )
                )
            },
            state = request.state,
        )

        val url = URLBuilder(request.redirectUrl!!)
            .apply { response.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()

        return AuthenticationResponseResult.Redirect(url, response)
    }

    internal suspend fun extractRequestForAuthorize(
        input: RequestParameters,
    ): Pair<AuthenticationRequestParameters, ClientBinding?> = when (input) {
        is AuthenticationRequestParameters -> {
            requirePushedAuthorizationRequests.let {
                if (it) throw InvalidRequest("pushed authorization request required, but got a plain request")
            }
            // can't authenticate client with plain auth request in browser
            input to null
        }

        is JarRequestParameters -> input.requestUri?.let {
            val storedRequest = requestUriToPushedAuthorizationRequest.remove(it)
                ?: throw InvalidRequest("request_uri not found: $it")
            if (storedRequest.request.clientId != input.clientId)
                throw InvalidRequest("client_id not matching from par: ${input.clientId} vs ${storedRequest.request.clientId}")
            storedRequest.request to storedRequest.clientBinding
        } ?: run {
            if (requirePushedAuthorizationRequests)
                throw InvalidRequest("pushed authorization request required, but got request object by value")
            val request = requestParser.extractRequest(input, null)?.parameters as? AuthenticationRequestParameters
                ?: throw InvalidRequest("could not parse request object from request")
            if (input.clientId != request.clientId)
                throw InvalidRequest("client_id not matching from par: ${input.clientId} vs ${request.clientId}")
            request to null
        }

        is RequestObjectParameters -> throw InvalidRequest("could not parse request object from request")
        is SignatureRequestParameters -> throw InvalidRequest("could not parse request object from request")
        is RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper ->
            throw InvalidRequest("could not parse request object from request")
    }

    /**
     * Validates basic requirements to [AuthenticationRequestParameters]:
     *  * [AuthenticationRequestParameters.redirectUrl] needs to be set
     *  * [AuthenticationRequestParameters.codeChallenge] needs to be set, with method `S256` (RFC 7636)
     *  * [AuthenticationRequestParameters.issuerState] needs to conform to our internal state
     *  * [AuthenticationRequestParameters.scope] is validated by [strategy]
     *  * [AuthenticationRequestParameters.authorizationDetails] are validated by [strategy]
     *
     * @return the request with [AuthenticationRequestParameters.scope] reduced to the values [strategy] accepts,
     * so that unvalidated input from the client is not carried into the authorization code or the access token
     */
    private suspend fun AuthenticationRequestParameters.validate(
        validateIssuerState: Boolean = true,
    ): AuthenticationRequestParameters {
        require(redirectUrl != null) { "redirect_uri not set" }
        if (codeChallenge == null)
            throw InvalidRequest("code_challenge not set")
        if (codeChallengeMethod != OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256)
            throw InvalidRequest("code_challenge_method not supported: $codeChallengeMethod")
        val filteredScope = scope?.let {
            strategy.filterScope(it)
                ?: throw InvalidScope("No matching scope in $it")
        }
        authorizationDetails?.let {
            strategy.validateAuthorizationDetails(it)
        }
        if (validateIssuerState && issuerState != null) {
            // The wallet could have started an auth code flow without any credential offer,
            // so the issuerState may be in fact null.
            if (!issuerStateService.verifyAndRemove(issuerState!!))
                throw InvalidGrant("issuer_state invalid: $issuerState")
            val credentialOffer = issuerStateToCredentialOffer.remove(issuerState!!)
                ?: throw InvalidGrant("issuer_state invalid: $issuerState")
            if (scope != null) {
                if (!strategy.validateScope(scope!!, credentialOffer.configurationIds))
                    throw InvalidScope("Scope not from credential offer: $scope")
            }
            if (authorizationDetails != null) {
                if (!strategy.validateAuthorizationDetails(authorizationDetails!!, credentialOffer.configurationIds))
                    throw InvalidAuthorizationDetails("AuthnDetails not from credential offer: $authorizationDetails")
            }
        }

        return copy(scope = filteredScope)
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token, uses [tokenService].
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client, to validate authentication
     *
     * @return [KmmResult] may contain a [OAuth2Exception], especially a [UseDpopNonce] or [UseAttestationChallenge]
     */
    override suspend fun token(
        request: TokenRequestParameters,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("token called with $request")
        val validatedClientKey = httpRequest?.validatedClientKey()
        val presentedClient = clientAuthenticationService.authenticateClient(
            httpRequest = httpRequest,
            clientId = request.clientId,
            validatedClientKey = validatedClientKey
        ).getOrThrow()
            ?: throw InvalidGrant("client_id not set")

        if (request.grantType == OpenIdConstants.GRANT_TYPE_TOKEN_EXCHANGE) {
            if (!supportTokenExchange)
                throw UnsupportedGrantType("token exchange not supported")
            val userInfoEndpoint = metadata().userInfoEndpoint
                ?: throw InvalidGrant("token_exchange requires userInfoEndpoint")
            return@catching tokenService.tokenExchange(
                request = request,
                expectedResource = userInfoEndpoint,
                httpRequest = httpRequest,
                validatedClientKey = validatedClientKey
            ).getOrThrow()
        }

        val clientAuthRequest = request.loadClientAuthnRequest(httpRequest, validatedClientKey)
            ?: throw InvalidGrant("could not load user info for $request")

        clientAuthRequest.clientBinding?.let { expectedClient ->
            if (!expectedClient.accepts(presentedClient))
                throw InvalidGrant("code was issued to a different client")
            if (request.clientId != null && request.clientId != expectedClient.clientId)
                throw InvalidGrant("client_id does not match authorization code")
        }

        if (request.grantType == OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE) {
            when {
                clientAuthRequest.transactionCode == null && request.transactionCode != null ->
                    throw InvalidRequest("tx_code was not expected")

                clientAuthRequest.transactionCode != null && request.transactionCode == null ->
                    throw InvalidRequest("tx_code required by the credential offer")

                clientAuthRequest.transactionCode != request.transactionCode ->
                    throw InvalidGrant("tx_code not matching the one from the credential offer")
            }

            val preAuthorizedCode = request.preAuthorizedCode
                ?: throw InvalidGrant("pre-authorized code not valid: ${request.preAuthorizedCode}")
            if (!preAuthorizedCodeService.verifyAndRemove(preAuthorizedCode))
                throw InvalidGrant("pre-authorized code not valid: $preAuthorizedCode")
            codeToClientAuthRequest.remove(preAuthorizedCode)
        }

        if (request.grantType == OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE) {
            validateCodeChallenge(
                code = request.code
                    ?: throw InvalidGrant("code not set"),
                codeVerifier = request.codeVerifier,
                // Authorization requests are rejected without one, so a code that has none was not issued by us
                codeChallenge = clientAuthRequest.codeChallenge
                    ?: throw InvalidGrant("no code_challenge stored for this code")
            )
        }
        val token = if (request.authorizationDetails != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = strategy.matchAndFilterAuthorizationDetailsForTokenResponse(
                    clientAuthRequest.authnDetails,
                    request.authorizationDetails!!
                ),
                scope = null,
                validatedClientKey = validatedClientKey,
            )
        } else if (request.scope != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = request.validatedScope(clientAuthRequest),
                validatedClientKey = validatedClientKey,
            )
        } else if (clientAuthRequest.authnDetails != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = strategy.filterAuthorizationDetailsForTokenResponse(clientAuthRequest.authnDetails),
                scope = null,
                validatedClientKey = validatedClientKey,
            )
        } else if (clientAuthRequest.scope != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = strategy.filterScope(clientAuthRequest.scope)
                    ?: throw InvalidScope("No valid scope in ${clientAuthRequest.scope}"),
                validatedClientKey = validatedClientKey,
            )
        } else {
            throw InvalidRequest("neither authorization details nor scope in request")
        }
        token.refreshToken?.let {
            refreshTokenToAuthRequest.put(
                key = it,
                value = clientAuthRequest.copy(
                    clientBinding = clientAuthRequest.clientBinding ?: presentedClient
                )
            )
        }
        Napier.i("token returns $token")
        token
    }

    /**
     * Like [token], but also provides a fresh DPoP nonce for the success response header.
     * See [RFC 9449 8. Authorization Server-Provided Nonce](https://datatracker.ietf.org/doc/html/rfc9449#section-8)
     */
    suspend fun tokenWithDpopNonce(
        request: TokenRequestParameters,
        httpRequest: RequestInfo? = null,
    ): KmmResult<ResponseWithDpopNonce<TokenResponseParameters>> = catching {
        val response = token(request, httpRequest).getOrThrow()
        ResponseWithDpopNonce(response, tokenService.dpopNonce())
    }

    private fun validateCodeChallenge(code: String, codeVerifier: String?, codeChallenge: String) {
        if (codeVerifier == null) {
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
        val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
        if (codeChallenge != codeChallengeCalculated) {
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
    }

    private fun TokenRequestParameters.validatedScope(clientAuthnRequest: ClientAuthRequest): String? {
        if (clientAuthnRequest.scope == null)
            throw InvalidRequest("Scope not from auth code: ${scope}, for code ${clientAuthnRequest.issuedCode}")
        val requested = scope.orEmpty().split(" ").filter(String::isNotBlank).toSet()
        val granted = clientAuthnRequest.scope.split(" ").filter(String::isNotBlank).toSet()
        if (!granted.containsAll(requested))
            throw InvalidRequest("Not all scopes from auth code: $requested")
        clientAuthnRequest.configurationIds?.let { configurationIds ->
            if (!strategy.validateScope(scope!!, configurationIds))
                throw InvalidScope("Scope not from credential offer: $scope")
        }
        return scope
    }

    internal suspend fun TokenRequestParameters.loadClientAuthnRequest(
        httpRequest: RequestInfo?,
        validatedClientKey: JsonWebKey?,
    ): ClientAuthRequest? = when (grantType) {
        OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
            if (code == null || !codeService.verifyAndRemove(code!!)) {
                throw InvalidCode("code not valid: $code")
            }
            code?.let { codeToClientAuthRequest.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
            if (preAuthorizedCode == null) {
                throw InvalidGrant("pre-authorized code not valid: $preAuthorizedCode")
            }
            preAuthorizedCode?.let { codeToClientAuthRequest.get(it) }
        }

        OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN -> {
            if (refreshToken == null) {
                throw InvalidGrant("refresh_token is null")
            }
            tokenService.verification.validateRefreshToken(refreshToken!!, httpRequest, validatedClientKey)
            refreshToken?.let { refreshTokenToAuthRequest.remove(it) }
        }

        else -> throw InvalidRequest("grant_type invalid")
    }

    /**
     * @param configurationIds restrict the code to these credential configuration IDs, i.e. the ones from the
     * credential offer it belongs to. Pass `null` to grant everything [strategy] supports.
     * @param transactionCode the client has to present this value in the token request, see
     * [offerWithPreAuthnForUserForSchemes]
     */
    @JvmOverloads
    suspend fun providePreAuthorizedCode(
        userInfo: OidcUserInfoExtended,
        configurationIds: Set<String>? = null,
        transactionCode: String? = null,
    ): String = preAuthorizedCodeService.provideCode().also {
        codeToClientAuthRequest.put(
            it,
            ClientAuthRequest(
                issuedCode = it,
                userInfo = userInfo,
                scope = strategy.validScopes(),
                authnDetails = strategy.validAuthorizationDetails(publicContext)
                    .filterForConfigurationIds(configurationIds),
                configurationIds = configurationIds,
                transactionCode = transactionCode,
            )
        )
    }

    /** Keeps only the authorization details for [configurationIds], i.e. the ones the credential offer contained. */
    private fun Collection<AuthorizationDetails>.filterForConfigurationIds(
        configurationIds: Set<String>?,
    ): Collection<AuthorizationDetails> = configurationIds?.let { ids ->
        filter { it !is OpenIdAuthorizationDetails || it.credentialConfigurationId in ids }
    } ?: this

    /**
     * Returns the user info associated with this access token, when the token in [authorizationHeader] is correct.
     *
     * @return [KmmResult] may contain a [OAuth2Exception], especially a [UseDpopNonce] or [UseAttestationChallenge]
     */
    override suspend fun userInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject> = catching {
        // The user info comes out of the validation itself, so it must not be looked up a second time
        tokenService.validateAccessToken(
            authorizationHeader = authorizationHeader,
            httpRequest = httpRequest,
            validatedClientKey = null,
        ).getOrThrow()
            .userInfoExtended?.jsonObject
            ?: throw InvalidGrant("no user info found for $authorizationHeader")
    }

    /**
     * Like [userInfo], but also provides a fresh DPoP nonce for the success response header.
     * See [RFC 9449 9. Resource Server-Provided Nonce](https://datatracker.ietf.org/doc/html/rfc9449#section-9)
     */
    suspend fun userInfoWithDpopNonce(
        authorizationHeader: String,
        httpRequest: RequestInfo? = null,
    ): KmmResult<ResponseWithDpopNonce<JsonObject>> = catching {
        val response = userInfo(authorizationHeader, httpRequest).getOrThrow()
        ResponseWithDpopNonce(response, tokenService.dpopNonce())
    }

    /**
     * Obtains a JSON object representing [at.asitplus.openid.OidcUserInfo] from the Authorization Server, and
     * since we're implementing [OAuth2AuthorizationServerAdapter] here, this is the same as [userInfo],
     * i.e. the access token is validated before any user info is returned.
     */
    override suspend fun getUserInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject> = userInfo(authorizationHeader, httpRequest)

    /**
     * Obtains information about the token, since we're in-memory here (as an [OAuth2AuthorizationServerAdapter]),
     * we can directly access our [tokenService].
     */
    override suspend fun getTokenInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenInfo> = catching {
        tokenService.verification.getTokenInfo(authorizationHeader)
    }

    override suspend fun tokenIntrospection(
        acceptHeader: String,
        request: TokenIntrospectionRequestContent,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenIntrospectionResponse> = catching {
        val validatedClientKey = httpRequest?.validatedClientKey()
        clientAuthenticationService.authenticateClient(
            httpRequest = httpRequest,
            clientId = null,
            validatedClientKey = validatedClientKey
        ).getOrThrow()
        val responseFormat = parseAcceptHeaderForTokenIntrospection(acceptHeader)
        val response = catchingUnwrapped {
            tokenService.verification.getTokenInfo(request.token)
        }.fold(
            onSuccess = {
                TokenIntrospectionResponseJson(
                    active = true,
                    scope = it.scope,
                    authorizationDetails = it.authorizationDetails,
                )
            },
            onFailure = {
                TokenIntrospectionResponseJson(active = false)
            }
        )

        when (responseFormat) {
            ContentType.Application.Json -> response

            ContentType.Application.IntrospectionJwt -> TokenIntrospectionResponseJwt(
                signIntrospectionJwt(
                    JwsContentTypeConstants.TOKEN_INTROSPECTION_JWT,
                    TokenIntrospectionResponseJwtPayload(
                        issuer = "foo", //TODO
                        audience = "bar", //TODO
                        iat = Clock.System.now(),
                        tokenIntrospection = response
                    ),
                    TokenIntrospectionResponseJwtPayload.serializer()
                ).getOrThrow()
            )

            else -> throw InvalidRequest("accept_header invalid")
        }
    }

    override suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<ValidatedAccessToken> = tokenService.validateAccessToken(
        authorizationHeader = authorizationHeader,
        httpRequest = httpRequest,
        validatedClientKey = null,
    )

    override suspend fun getDpopNonce() = tokenService.dpopNonce()

    /** Extracts and validated the DPoP proof, if there is any */
    private suspend fun RequestInfo?.validatedClientKey(): JsonWebKey? =
        this?.dpop?.let { tokenService.verification.extractValidatedClientKey(this).getOrThrow() }
}

/**
 * Implements [RFC 9449 8.2.](https://datatracker.ietf.org/doc/html/rfc9449#name-providing-a-new-nonce-value):
 * Authorization servers may include a fresh DPoP nonce by including values in HTTP 200 responses
 */
data class ResponseWithDpopNonce<T>(
    val response: T,
    /** Set as HTTP header `DPoP-Nonce` in the response, see [HttpHeaders.DPoPNonce] */
    val dpopNonce: String?,
)

/**
 * Internal class used to store pushed authorization requests created for clients in
 * [SimpleAuthorizationService.requestUriToPushedAuthorizationRequest],
 * which are referenced by a `request_uri` and fetched later on in the process.
 *
 * Needs to be public to allow for implementations of [MapStore] with this type.
 */
data class PushedAuthorizationRequest(
    val request: AuthenticationRequestParameters,
    val clientBinding: ClientBinding
)

private fun parseAcceptHeaderForTokenIntrospection(acceptHeader: String) = acceptHeader
    .let(::parseHeaderValue)
    .sortedByDescending { it.quality }
    .map { ContentType.parse(it.value) }
    .firstOrNull {
        it == ContentType.Application.Json || it == ContentType.Application.IntrospectionJwt
    } ?: throw IllegalArgumentException("Accept header is mandatory to specify answer format")
