package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidvci.*
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * with the actual authentication and authorization logic implemented in [strategy].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
 */
class SimpleAuthorizationService(
    /**
     * Used to load user data and filter authorization details
     */
    private val strategy: AuthorizationServiceStrategy,
    /**
     * Used to create and verify authorization codes during issuing.
     */
    private val codeService: CodeService = DefaultCodeService(),
    /**
     * Used to create and verify bearer tokens during issuing.
     */
    private val tokenService: NonceService = DefaultNonceService(),
    /**
     * Used to provide challenge to clients to include in proof of possession of key material.
     */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /**
     * Used to generate request uris on pushed authorization requests in [par]
     */
    private val requestUriService: NonceService = DefaultNonceService(),
    /**
     * Used in several fields in [OAuth2AuthorizationServerMetadata], to provide endpoint URLs to clients.
     */
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
    private val codeToUserInfoStore: MapStore<String, IssuedCode> = DefaultMapStore(),
    private val accessTokenToUserInfoStore: MapStore<String, IssuedAccessToken> = DefaultMapStore(),
    private val requestUriToPushedAuthorizationRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /**
     * Enforce client authentication as defined in OpenID4VC HAIP, i.e. with wallet attestations
     */
    private val enforceClientAuthentication: Boolean = false,
    /** Used to verify client attestation JWTs */
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    /** Callback to verify the client attestation JWT against a set of trusted roots */
    private val verifyClientAttestationJwt: (suspend (JwsSigned<JsonWebToken>) -> Boolean) = { true },
) : OAuth2AuthorizationServerAdapter {

    override val supportsClientNonce: Boolean = true
    override val supportsPushedAuthorizationRequests: Boolean = true

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION]
     */
    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
            pushedAuthorizationRequestEndpoint = "$publicContext$pushedAuthorizationRequestEndpointPath",
            requirePushedAuthorizationRequests = true, // per OID4VC HAIP
            tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH), // per OID4VC HAIP
        )
    }

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     */
    suspend fun par(
        request: AuthenticationRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ) = catching {
        Napier.i("pushedAuthorization called with $request")

        if (request.requestUri != null) {
            Napier.w("par: client set request_uri: ${request.requestUri}")
            throw OAuth2Exception(Errors.INVALID_REQUEST, "request_uri must not be set")
        }

        authenticateClient(clientAttestation, clientAttestationPop, request.clientId)
        validateAuthnRequest(request)

        val requestUri = "urn:ietf:params:oauth:request_uri:${requestUriService.provideNonce()}".also {
            requestUriToPushedAuthorizationRequestStore.put(it, request)
        }
        PushedAuthenticationResponseParameters(
            requestUri = requestUri,
            expires = 5.minutes,
        )
    }

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    suspend fun authorize(input: AuthenticationRequestParameters) = catching {
        Napier.i("authorize called with $input")

        val request = if (input.requestUri != null) {
            val par = requestUriToPushedAuthorizationRequestStore.remove(input.requestUri!!)
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "request_uri set, but not found")
                    .also { Napier.w("authorize: client sent invalid request_uri: ${input.requestUri}") }
            if (par.clientId != input.clientId) {
                throw OAuth2Exception(Errors.INVALID_REQUEST, "client_id not matching from par")
                    .also { Napier.w("authorize: invalid client_id: ${input.clientId} vs par ${par.clientId}") }
            }
            par
        } else {
            input
        }
        validateAuthnRequest(request)

        val code = codeService.provideCode().also { code ->
            val userInfo = strategy.loadUserInfo(request, code)
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "Could not load user info for code=$code")
                    .also { Napier.w("authorize: could not load user info from $request") }
            codeToUserInfoStore.put(
                code,
                IssuedCode(
                    code = code,
                    userInfoExtended = userInfo,
                    scope = request.scope,
                    authorizationDetails = request.authorizationDetails,
                    codeChallenge = request.codeChallenge
                )
            )
        }
        val response = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )

        val url = URLBuilder(request.redirectUrl!!)
            .apply { response.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()

        AuthenticationResponseResult.Redirect(url, response)
            .also { Napier.i("authorize returns $it") }
    }

    // TODO Also enable JWT-Secured Authorization Request (JAR) RFC9101
    private fun validateAuthnRequest(request: AuthenticationRequestParameters) {
        if (request.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST, "redirect_uri not set")
                .also { Napier.w("authorize: client did not set redirect_uri in $request") }

        if (request.scope != null) {
            strategy.filterScope(request.scope!!)
                ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No matching scope in ${request.scope}")
                    .also { Napier.w("authorize: scope ${request.scope} does not contain a valid credential id") }
        }

        if (request.authorizationDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(request.authorizationDetails!!)
            if (filtered.isEmpty()) {
                throw OAuth2Exception(Errors.INVALID_REQUEST, "No matching authorization details")
                Napier.w("authorize: authorization details not valid: ${request.authorizationDetails}")
            }
        }
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(
        request: TokenRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ) = catching {
        Napier.i("token called with $request")

        val issuedCode: IssuedCode = request.loadIssuedCode()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "could not load user info for $request")
                .also { Napier.w("token: could not load user info for $request}") }

        request.code?.let { code ->
            validateCodeChallenge(code, request.codeVerifier)
        }

        authenticateClient(clientAttestation, clientAttestationPop, request.clientId)

        val response = TokenResponseParameters(
            accessToken = tokenService.provideNonce(),
            tokenType = OpenIdConstants.TOKEN_TYPE_BEARER,
            expires = 3600.seconds,
            clientNonce = clientNonceService.provideNonce(),
        )

        if (request.authorizationDetails != null) {
            if (issuedCode.authorizationDetails == null)
                throw OAuth2Exception(
                    Errors.INVALID_REQUEST,
                    "Authorization details not from auth code: ${request.authorizationDetails}, was ${issuedCode.authorizationDetails}"
                )

            val filtered = strategy.filterAuthorizationDetails(request.authorizationDetails!!)
            if (filtered.isEmpty())
                throw OAuth2Exception(
                    Errors.INVALID_REQUEST,
                    "No valid authorization details in ${request.authorizationDetails}"
                )

            filtered.forEach { filter ->
                if (!filter.requestedFromCode(issuedCode))
                    throw OAuth2Exception(Errors.INVALID_REQUEST, "Authorization details not from auth code: $filter")
            }
            response
                .copy(authorizationDetails = filtered)
                .also {
                    response.accessToken.store(issuedCode, filtered)
                    Napier.i("token returns $it")
                }
        } else if (request.scope != null) {
            if (issuedCode.scope == null)
                throw OAuth2Exception(
                    Errors.INVALID_REQUEST,
                    "Scope not from auth code: ${request.scope}, was ${issuedCode.scope}"
                )

            val scope = strategy.filterScope(request.scope!!)
                ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No valid scope in ${request.scope}")

            scope.split(" ").forEach { singleScope ->
                if (!issuedCode.scope.contains(singleScope))
                    throw OAuth2Exception(Errors.INVALID_REQUEST, "Scope not from auth code: $singleScope")
            }

            response
                .copy(scope = scope)
                .also {
                    response.accessToken.store(issuedCode, scope)
                    Napier.i("token returns $it")
                }
        } else if (issuedCode.authorizationDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(
                issuedCode.authorizationDetails.filterIsInstance<OpenIdAuthorizationDetails>()
            )
            if (filtered.isEmpty())
                throw OAuth2Exception(
                    Errors.INVALID_REQUEST,
                    "No valid authorization details in ${issuedCode.authorizationDetails}"
                )

            response
                .copy(authorizationDetails = filtered)
                .also {
                    response.accessToken.store(issuedCode, filtered)
                    Napier.i("token returns $it")
                }
        } else if (issuedCode.scope != null) {
            val scope = strategy.filterScope(issuedCode.scope)
                ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No valid scope in ${issuedCode.scope}")

            response
                .copy(scope = scope)
                .also {
                    response.accessToken.store(issuedCode, scope)
                    Napier.i("token returns $it")
                }
        } else {
            Napier.w("token: request can not be parsed: $request")
            throw OAuth2Exception(Errors.INVALID_REQUEST, "neither authorization details nor scope in request")
        }
    }

    /**
     * Authenticates the client as defined in OpenID4VC HAIP, i.e. with client attestation JWT
     */
    private suspend fun authenticateClient(
        clientAttestation: String?,
        clientAttestationPop: String?,
        clientId: String?,
    ) {
        // Enforce client authentication once all clients implement it
        if (enforceClientAuthentication) {
            if (clientAttestation == null || clientAttestationPop == null) {
                Napier.w("auth: client not sent client attestation")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation headers missing")
            }
        }
        if (clientAttestation != null && clientAttestationPop != null) {
            val clientAttestationJwt = JwsSigned
                .deserialize<JsonWebToken>(JsonWebToken.serializer(), clientAttestation, vckJsonSerializer)
                .getOrElse {
                    Napier.w("auth: could not parse client attestation JWT", it)
                    throw OAuth2Exception(Errors.INVALID_CLIENT, "could not parse client attestation", it)
                }
            if (!verifierJwsService.verifyJwsObject(clientAttestationJwt)) {
                Napier.w("auth: client attestation JWT not verified")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation JWT not verified")
            }
            if (clientAttestationJwt.payload.subject != clientId) {
                Napier.w("auth: subject ${clientAttestationJwt.payload.subject} not matching client_id $clientId")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "subject not equal to client_id")
            }

            if (!verifyClientAttestationJwt.invoke(clientAttestationJwt)) {
                Napier.w("auth: client attestation not verified by callback: $clientAttestationJwt")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation not verified")
            }

            val clientAttestationPopJwt = JwsSigned
                .deserialize<JsonWebToken>(JsonWebToken.serializer(), clientAttestationPop, vckJsonSerializer)
                .getOrElse {
                    Napier.w("auth: could not parse client attestation PoP JWT", it)
                    throw OAuth2Exception(Errors.INVALID_CLIENT, "could not parse client attestation PoP", it)
                }
            val cnf = clientAttestationJwt.payload.confirmationClaim
                ?: throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation has no cnf")
            if (!verifierJwsService.verifyJws(clientAttestationPopJwt, cnf)) {
                Napier.w("auth: client attestation PoP JWT not verified")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation PoP JWT not verified")
            }
        }
    }

    private fun OpenIdAuthorizationDetails.requestedFromCode(issuedCode: IssuedCode): Boolean =
        issuedCode.authorizationDetails!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    private suspend fun String.store(issuedCode: IssuedCode, filtered: Set<OpenIdAuthorizationDetails>) {
        accessTokenToUserInfoStore.put(this, IssuedAccessToken(this, issuedCode.userInfoExtended, filtered))
    }

    private suspend fun String.store(issuedCode: IssuedCode, scope: String) {
        accessTokenToUserInfoStore.put(this, IssuedAccessToken(this, issuedCode.userInfoExtended, scope))
    }

    private suspend fun validateCodeChallenge(code: String, codeVerifier: String?) {
        codeToUserInfoStore.get(code)?.codeChallenge?.let { codeChallenge ->
            if (codeVerifier == null) {
                Napier.w("token: client did not provide any code verifier: $codeVerifier for $code")
                throw OAuth2Exception(Errors.INVALID_GRANT, "code verifier invalid: $codeVerifier for $code")
            }
            val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
            if (codeChallenge != codeChallengeCalculated) {
                Napier.w("token: client did not provide correct code verifier: $codeVerifier for $code")
                throw OAuth2Exception(Errors.INVALID_GRANT, "code verifier invalid: $codeVerifier for $code")
            }
        }
    }

    private suspend fun TokenRequestParameters.loadIssuedCode(): IssuedCode? = when (grantType) {
        OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
            if (code == null || !codeService.verifyAndRemove(code!!))
                throw OAuth2Exception(Errors.INVALID_CODE, "code not valid: $code")
                    .also { Napier.w("token: client did not provide correct code: $code") }
            code?.let { codeToUserInfoStore.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
            if (preAuthorizedCode == null || !codeService.verifyAndRemove(preAuthorizedCode!!))
                throw OAuth2Exception(Errors.INVALID_GRANT, "pre-authorized code not valid: $preAuthorizedCode")
                    .also { Napier.w("token: pre-authorized code not valid: $preAuthorizedCode") }
            preAuthorizedCode?.let { codeToUserInfoStore.remove(it) }
        }

        else -> throw OAuth2Exception(Errors.INVALID_REQUEST, "grant_type invalid")
            .also { Napier.w("token: client did not provide valid grant_type: $grantType") }
    }

    override suspend fun providePreAuthorizedCode(user: OidcUserInfoExtended): String =
        codeService.provideCode().also {
            codeToUserInfoStore.put(
                it,
                IssuedCode(it, user, strategy.validScopes(), strategy.validAuthorizationDetails())
            )
        }

    override suspend fun verifyClientNonce(nonce: String): Boolean =
        clientNonceService.verifyNonce(nonce)

    /**
     * Get the [OidcUserInfoExtended] (holding [at.asitplus.openid.OidcUserInfo]) associated with the [accessToken],
     * that was created before at the Authorization Server.
     *
     * Also validates that the client has really requested a credential (either identified by [credentialIdentifier]
     * or [credentialConfigurationId]) that has been allowed by this access token issued in [token].
     */
    override suspend fun getUserInfo(
        accessToken: String,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
    ): KmmResult<OidcUserInfoExtended> = catching {
        if (!tokenService.verifyNonce(accessToken))
            throw OAuth2Exception(INVALID_TOKEN, "access token not valid: $accessToken")

        val result = accessTokenToUserInfoStore.get(accessToken)
            ?: throw OAuth2Exception(INVALID_TOKEN, "could not load user info for access token $accessToken")
        if (credentialIdentifier != null) {
            if (result.authorizationDetails == null)
                throw OAuth2Exception(
                    INVALID_TOKEN,
                    "no authorization details stored for access token $accessToken"
                )
            val validCredentialIdentifiers = result.authorizationDetails.flatMap { it.credentialIdentifiers ?: setOf() }
            if (!validCredentialIdentifiers.contains(credentialIdentifier))
                throw OAuth2Exception(
                    INVALID_TOKEN,
                    "credential_identifier expected to be in ${validCredentialIdentifiers}, but got $credentialIdentifier"
                )
        } else if (credentialConfigurationId != null) {
            if (result.scope == null)
                throw OAuth2Exception(INVALID_TOKEN, "no scope stored for access token $accessToken")
            if (!result.scope.contains(credentialConfigurationId))
                throw OAuth2Exception(
                    INVALID_TOKEN,
                    "credential_configuration_id expected to be ${result.scope}, but got $credentialConfigurationId"
                )

        } else {
            throw OAuth2Exception(INVALID_TOKEN, "neither credential_identifier nor credential_configuration_id set")
        }

        result.userInfoExtended
            .also { Napier.v("getUserInfo returns $it") }
    }

    override suspend fun provideMetadata() = KmmResult.success(metadata)
}
