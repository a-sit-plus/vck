package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.IntrospectionJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondIncludingDpopNonce
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.DPoP
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.NoopClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestationChallenge
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestationPop
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import io.github.aakira.napier.Napier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

val OAuth2KtorClientTest by matrixSuite {

    data class Context(
        val clientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val authorizationService: SimpleAuthorizationService,
        val credentialIssuer: CredentialIssuer,
        val client: OAuth2KtorClient,
        val issuedAttestationChallenges: List<String>,
        val receivedPopChallenges: List<String?>,
    )

    fun setup(
        strategy: CredentialAuthorizationServiceStrategy,
        requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>?,
        requirePAR: Boolean,
        captureAttestationInput: ((OAuth2KtorClient.LoadInstanceAttestationInput) -> Unit)? = null,
        serveChallengeEndpoint: Boolean = true,
        requireChallengeRetry: Boolean = false,
        provideChallengeOnParSuccess: Boolean = false,
        popMethods: Set<ClientAttestationPopMethod>? = setOf(ClientAttestationPopMethod.AttestationPopJwt),
        dpopAlgorithms: Set<JwsAlgorithm.Signature> = setOf(JwsAlgorithm.Signature.ES256),
        /** DPoP combined mode has a single key: the attested key is also the DPoP key. */
        useSingleKey: Boolean = false,
    ): Context {
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val introspectionEndpointPath = "/introspect"
        val parEndpointPath = "/par"
        val challengeEndpointPath = "/challenge"
        val publicContext = "https://issuer.example.com"
        // In DPoP combined mode the attestation challenge is carried in the DPoP proof's nonce, so both stores
        // must be the same instance for a challenge to be accepted as a DPoP nonce
        val proofNonceService = DefaultNonceService()
        val authorizationService = SimpleAuthorizationService(
            strategy = strategy,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = popMethods?.let {
                AttestationBasedClientAuthenticationService(
                    acceptedPopMethods = it,
                    nonceService = proofNonceService,
                )
            } ?: NoopClientAuthenticationService,
            tokenService = TokenService.jwt(
                issueRefreshTokens = true,
                dpopNonceService = proofNonceService,
                verificationAlgorithms = dpopAlgorithms,
            ),
            requestObjectSigningAlgorithms = requestObjectSigningAlgorithms,
            requirePushedAuthorizationRequests = requirePAR,
        )
        val credentialIssuer = CredentialIssuer(
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            authorizationService = authorizationService,
            credentialSchemes = AttributeIndex.schemeSet,
        )
        val issuedAttestationChallenges = mutableListOf<String>()
        val receivedPopChallenges = mutableListOf<String?>()
        var challengeRetryRequired = requireChallengeRetry
        val mockEngine = MockEngine { request ->
            when {
                request.url.fullPath.startsWith(challengeEndpointPath) && serveChallengeEndpoint -> {
                    val response = authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
                    issuedAttestationChallenges += response.attestationChallenge
                    respond(
                        joseCompliantSerializer.encodeToString(AttestationChallengeResponse.serializer(), response),
                        headers = headers {
                            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            append(HttpHeaders.CacheControl, "no-store")
                        },
                    )
                }

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
                    if (challengeRetryRequired) {
                        challengeRetryRequired = false
                        val challenge = authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
                            .attestationChallenge
                            .also { issuedAttestationChallenges += it }
                        // PAR mandates a fresh DPoP nonce, and the client retries only once, so an AS rejecting the
                        // request for a missing attestation challenge must supply the nonce in the same response.
                        return@MockEngine respondOAuth2Error(
                            OAuth2Exception.UseAttestationChallenge(challenge),
                            dpopNonce = authorizationService.getDpopNonce(),
                        )
                    }
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
                    authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = {
                            if (provideChallengeOnParSuccess) {
                                val challenge = authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
                                    .attestationChallenge
                                    .also { issuedAttestationChallenges += it }
                                respond(
                                    joseCompliantSerializer.encodeToString(
                                        PushedAuthenticationResponseParameters.serializer(),
                                        it.response,
                                    ),
                                    headers = headers {
                                        append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                                        it.dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) }
                                        append(HttpHeaders.OAuthClientAttestationChallenge, challenge)
                                    },
                                )
                            } else {
                                respondIncludingDpopNonce(it)
                            }
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { respondOAuth2Error(it) },
                    )
                }

                request.url.fullPath.startsWith(introspectionEndpointPath) -> {
                    receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenIntrospectionRequest =
                        requestBody.decodeFromPostBody<TokenIntrospectionRequest>()
                    val acceptHeader: String = request.headers[HttpHeaders.Accept].shouldNotBeNull()
                    authorizationService.tokenIntrospection(acceptHeader, params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) },
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
        return Context(
            clientAuthKeyMaterial = clientAuthKeyMaterial,
            mockEngine = mockEngine,
            authorizationService = authorizationService,
            credentialIssuer = credentialIssuer,
            client = OAuth2KtorClient(
                engine = mockEngine,
                loadInstanceAttestation = {
                    captureAttestationInput?.invoke(it)
                    catching {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = clientId,
                            clientKey = clientAuthKeyMaterial.jsonWebKey
                        )
                    }
                },
                keyMaterial = clientAuthKeyMaterial,
                dpopKeyMaterial = if (useSingleKey) clientAuthKeyMaterial else EphemeralKeyWithoutCert(),
                oAuth2Client = OAuth2Client(clientId = clientId),
                randomSource = RandomSource.Default,
            ),
            issuedAttestationChallenges = issuedAttestationChallenges,
            receivedPopChallenges = receivedPopChallenges,
        )
    }

    val strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet)
    val requestedScope = strategy.validScopes().split(" ").first()

    listOf<Pair<Boolean, Set<JwsAlgorithm.Signature>?>>(
        false to null,
        false to setOf(JwsAlgorithm.Signature.ES256),
        true to null,
        true to setOf(JwsAlgorithm.Signature.ES256),
    ).forEach { (requirePAR, enableJAR) ->
        test("auth code and token; JAR=${enableJAR != null} PAR=$requirePAR") {
            with(setup(strategy, enableJAR, requirePAR)) {
                client.startAuthorization(
                    oauthMetadata = authorizationService.metadata(),
                    authorizationServer = authorizationService.publicContext,
                    scope = requestedScope,
                ).getOrThrow().also {
                    // Simulates the browser, handling authorization to get the authCode
                    val httpClient = HttpClient(mockEngine) { followRedirects = false }
                    val authCodeUrl = httpClient.get(it.url).headers[HttpHeaders.Location].shouldNotBeNull()
                    client.requestTokenWithAuthCode(
                        oauthMetadata = authorizationService.metadata(),
                        url = authCodeUrl,
                        authorizationServer = authorizationService.publicContext,
                        state = it.state,
                        scope = requestedScope,
                        authorizationDetails = setOf()
                    ).getOrThrow().also {
                        it.params.accessToken.shouldNotBeNull()
                    }
                }
            }
        }
    }

    test("token introspection handles jwt response") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = false)) {
            val authorizationResult = client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()
            val httpClient = HttpClient(mockEngine) { followRedirects = false }
            val authCodeUrl = httpClient.get(authorizationResult.url).headers[HttpHeaders.Location].shouldNotBeNull()
            val tokenResponse = client.requestTokenWithAuthCode(
                oauthMetadata = authorizationService.metadata(),
                url = authCodeUrl,
                authorizationServer = authorizationService.publicContext,
                state = authorizationResult.state,
                scope = requestedScope,
                authorizationDetails = setOf()
            ).getOrThrow()

            client.callTokenIntrospection(
                oauthMetadata = authorizationService.metadata(),
                responseFormat = ContentType.Application.IntrospectionJwt,
                request = TokenIntrospectionRequest(
                    token = tokenResponse.params.accessToken,
                    tokenTypeHint = tokenResponse.params.tokenType,
                ),
                token = tokenResponse.params.accessToken,
                popAudience = authorizationService.publicContext,
            ).active shouldBe true
        }
    }

    test("applyAuthnForToken throws when keyMaterial does not match cnf key in instance attestation") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = false)) {
            val differentKey: KeyMaterial = EphemeralKeyWithoutCert()
            val clientAuthKey: KeyMaterial = EphemeralKeyWithoutCert()
            val mockEngine = MockEngine { respondOk() }
            val clientId = "https://example.com/rp-mismatch"

            val client = OAuth2KtorClient(
                engine = mockEngine,
                loadInstanceAttestation = {
                    catching {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = clientId,
                            clientKey = differentKey.jsonWebKey,  // WIA attests a different key
                        )
                    }
                },
                keyMaterial = clientAuthKey,  // PoP signed with this key — does not match cnf
                oAuth2Client = OAuth2Client(clientId = clientId),
                randomSource = RandomSource.Default,
            )

            shouldThrow<Exception> {
                client.applyAuthnForToken(
                    resourceUrl = "https://example.com/token",
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = authorizationService.metadata(),
                )
            }.message shouldContain "does not match"
        }
    }

    /**
     * draft-10 8 puts the client authentication method in `token_endpoint_auth_methods_supported`, while
     * `client_attestation_pop_methods_supported` (7.6) is about presenting an attestation as an *additional*
     * security signal and MAY be omitted, so the mode must be selected from the former.
     */
    test("sends a dedicated PoP when the AS advertises the auth method but no PoP methods") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = false)) {
            val metadata = authorizationService.metadata().copy(
                tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH),
                clientAttestationPopMethodsSupported = null,
            )

            val headers = HttpRequestBuilder().apply {
                client.applyAuthnForToken(
                    resourceUrl = "https://issuer.example.com/token",
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )()
            }.headers.build()

            headers[HttpHeaders.OAuthClientAttestation].shouldNotBeNull()
            headers[HttpHeaders.OAuthClientAttestationPop].shouldNotBeNull()
        }
    }

    test("combined mode metadata does not break a client that sends no attestation") {
        with(
            setup(
                strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = false,
                popMethods = setOf(ClientAttestationPopMethod.DpopCombined),
            )
        ) {
            // No loadInstanceAttestation, and the two keys are independent because none of them is attested
            val plainDpopClient = OAuth2KtorClient(
                engine = mockEngine,
                oAuth2Client = OAuth2Client(clientId = "https://example.com/rp-no-attestation"),
                randomSource = RandomSource.Default,
            )

            val headers = HttpRequestBuilder().apply {
                plainDpopClient.applyAuthnForToken(
                    resourceUrl = "https://issuer.example.com/token",
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = authorizationService.metadata(),
                )()
            }.headers.build()

            headers[HttpHeaders.OAuthClientAttestation].shouldBeNull()
            headers[HttpHeaders.DPoP].shouldNotBeNull()
        }
    }

    test("instance attestation callbacks receive authorization server context") {
        var attestationInput: OAuth2KtorClient.LoadInstanceAttestationInput? = null

        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                captureAttestationInput = { attestationInput = it },
            )
        ) {
            client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
                issuerMetadata = credentialIssuer.metadata,
            ).getOrThrow()

            attestationInput.shouldNotBeNull().also {
                it.authorizationServer shouldBe authorizationService.publicContext
                it.credentialIssuer shouldBe credentialIssuer.metadata.credentialIssuer
                it.preferredClientStatusPeriod shouldBe credentialIssuer.metadata.preferredClientStatusPeriod
            }
        }
    }
    test("fetches advertised attestation challenge for the PAR PoP") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = true)) {
            client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()

            // PAR mandates a fresh DPoP nonce, which the client can only learn from the rejected first attempt,
            // so two PARs are sent, each carrying a freshly fetched challenge in its PoP.
            receivedPopChallenges.size shouldBe 2
            receivedPopChallenges shouldBe issuedAttestationChallenges
        }
    }

    test("retries PAR with the DPoP nonce from the error response") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = true)) {
            client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()

            // The AS mandates a nonce at PAR (RFC 9449 8.), and the client has none for the first request
            val parDpopNonces = mockEngine.requestHistory
                .filter { it.url.fullPath.startsWith("/par") }
                .map { it.toRequestInfo().dpop.shouldNotBeNull().payload.nonce }
            parDpopNonces.size shouldBe 2
            parDpopNonces.first() shouldBe null
            parDpopNonces.last().shouldNotBeNull()
        }
    }

    test("fetches a fresh attestation challenge for every request") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = true)) {
            val authorization = client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()
            val httpClient = HttpClient(mockEngine) { followRedirects = false }
            val redirect = httpClient.get(authorization.url).headers[HttpHeaders.Location].shouldNotBeNull()

            client.requestTokenWithAuthCode(
                oauthMetadata = authorizationService.metadata(),
                url = redirect,
                authorizationServer = authorizationService.publicContext,
                state = authorization.state,
                scope = requestedScope,
                authorizationDetails = setOf(),
            ).getOrThrow()

            // A challenge is single-use on the server, so PAR and token must not share one
            receivedPopChallenges shouldBe issuedAttestationChallenges
            receivedPopChallenges.distinct() shouldBe receivedPopChallenges
        }
    }

    test("retries PAR once with attestation challenge from error response") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                serveChallengeEndpoint = false,
                requireChallengeRetry = true,
            )
        ) {
            client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()

            receivedPopChallenges shouldBe listOf(null, issuedAttestationChallenges.single())
        }
    }

    /**
     * DPoP combined mode, i.e. one DPoP proof also serving as the Client Attestation PoP, from sections 5.2 and 7.3
     * of [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     */
    val combinedMode = setOf(ClientAttestationPopMethod.DpopCombined)

    test("combined mode sends attestation and DPoP proof, but no dedicated PoP") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = true,
            )
        ) {
            val metadata = authorizationService.metadata()
            val resourceUrl = metadata.pushedAuthorizationRequestEndpoint.shouldNotBeNull()
            val builder = HttpRequestBuilder().apply(
                client.applyAuthnForToken(
                    resourceUrl = resourceUrl,
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )
            )
            val request = RequestInfo(resourceUrl, HttpMethod.Post, builder.headers.build())

            request.clientAttestation.shouldNotBeNull()
            request.dpop.shouldNotBeNull()
            // 5.2: the DPoP proof replaces the dedicated PoP, it does not accompany it
            request.clientAttestationPop.shouldBeNull()
        }
    }

    test("combined mode signs the DPoP proof with the attested key") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = true,
            )
        ) {
            val metadata = authorizationService.metadata()
            val resourceUrl = metadata.pushedAuthorizationRequestEndpoint.shouldNotBeNull()
            val builder = HttpRequestBuilder().apply(
                client.applyAuthnForToken(
                    resourceUrl = resourceUrl,
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )
            )
            val request = RequestInfo(resourceUrl, HttpMethod.Post, builder.headers.build())
            val attestedKey = request.clientAttestation.shouldNotBeNull()
                .payload.confirmationClaim.shouldNotBeNull()
                .jsonWebKey.shouldNotBeNull()
            val dpopKey = request.dpop.shouldNotBeNull().jws.jwsHeader.jsonWebKey.shouldNotBeNull()

            // Without this the DPoP proof says nothing about possession of the attested key
            dpopKey.jwkThumbprint shouldBe attestedKey.jwkThumbprint
        }
    }

    test("combined mode carries the attestation challenge as the DPoP nonce") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = true,
            )
        ) {
            val metadata = authorizationService.metadata()
            val resourceUrl = metadata.pushedAuthorizationRequestEndpoint.shouldNotBeNull()
            val builder = HttpRequestBuilder().apply(
                client.applyAuthnForToken(
                    resourceUrl = resourceUrl,
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )
            )
            val request = RequestInfo(resourceUrl, HttpMethod.Post, builder.headers.build())

            request.dpop.shouldNotBeNull().payload.nonce shouldBe issuedAttestationChallenges.single()
        }
    }

    test("combined mode completes the authorization code flow") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = true,
            )
        ) {
            val authorization = client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()
            val httpClient = HttpClient(mockEngine) { followRedirects = false }
            val redirect = httpClient.get(authorization.url).headers[HttpHeaders.Location].shouldNotBeNull()

            client.requestTokenWithAuthCode(
                oauthMetadata = authorizationService.metadata(),
                url = redirect,
                authorizationServer = authorizationService.publicContext,
                state = authorization.state,
                scope = requestedScope,
                authorizationDetails = setOf(),
            ).getOrThrow().params.accessToken.shouldNotBeNull()
        }
    }

    test("combined mode fails before sending when the attested key is not the DPoP key") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = false, // independent DPoP key cannot prove possession of the attested key
            )
        ) {
            shouldThrow<IllegalArgumentException> {
                client.startAuthorization(
                    oauthMetadata = authorizationService.metadata(),
                    authorizationServer = authorizationService.publicContext,
                    scope = requestedScope,
                ).getOrThrow()
            }

            // A request that cannot possibly authenticate must not be sent at all
            mockEngine.requestHistory.filter { it.url.fullPath.startsWith("/par") }.shouldBeEmpty()
        }
    }

    test("combined mode fails before sending when the AS advertises no usable DPoP algorithm") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = combinedMode,
                dpopAlgorithms = setOf(JwsAlgorithm.Signature.ES512), // client keys are ES256
                useSingleKey = true,
            )
        ) {
            shouldThrow<IllegalArgumentException> {
                client.startAuthorization(
                    oauthMetadata = authorizationService.metadata(),
                    authorizationServer = authorizationService.publicContext,
                    scope = requestedScope,
                ).getOrThrow()
            }

            // Combined mode without a DPoP proof is not a mode, so degrading silently must not happen
            mockEngine.requestHistory.filter { it.url.fullPath.startsWith("/par") }.shouldBeEmpty()
        }
    }

    test("normal mode is preferred when the AS advertises both auth methods") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                popMethods = setOf(
                    ClientAttestationPopMethod.AttestationPopJwt,
                    ClientAttestationPopMethod.DpopCombined,
                ),
                useSingleKey = false,
            )
        ) {
            val metadata = authorizationService.metadata()
            val resourceUrl = metadata.pushedAuthorizationRequestEndpoint.shouldNotBeNull()
            val builder = HttpRequestBuilder().apply(
                client.applyAuthnForToken(
                    resourceUrl = resourceUrl,
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )
            )
            val request = RequestInfo(resourceUrl, HttpMethod.Post, builder.headers.build())
            val attestedKey = request.clientAttestation.shouldNotBeNull()
                .payload.confirmationClaim.shouldNotBeNull()
                .jsonWebKey.shouldNotBeNull()
            val dpop = request.dpop.shouldNotBeNull()

            request.clientAttestationPop.shouldNotBeNull()
            dpop.payload.nonce.shouldBeNull()
            dpop.jws.jwsHeader.jsonWebKey.shouldNotBeNull().jwkThumbprint shouldNotBe attestedKey.jwkThumbprint
        }
    }

    test("no attestation headers when the AS advertises no attestation auth method") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = false,
                popMethods = null,
            )
        ) {
            val metadata = authorizationService.metadata()
            val resourceUrl = metadata.tokenEndpoint.shouldNotBeNull()
            val builder = HttpRequestBuilder().apply(
                client.applyAuthnForToken(
                    resourceUrl = resourceUrl,
                    httpMethod = HttpMethod.Post,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = metadata,
                )
            )
            val request = RequestInfo(resourceUrl, HttpMethod.Post, builder.headers.build())

            request.clientAttestation.shouldBeNull()
            request.clientAttestationPop.shouldBeNull()
        }
    }

    test("uses attestation challenge from PAR response for token request") {
        with(
            setup(
                strategy = strategy,
                requestObjectSigningAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                requirePAR = true,
                provideChallengeOnParSuccess = true,
            )
        ) {
            val authorization = client.startAuthorization(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                scope = requestedScope,
            ).getOrThrow()
            val httpClient = HttpClient(mockEngine) { followRedirects = false }
            val redirect = httpClient.get(authorization.url).headers[HttpHeaders.Location].shouldNotBeNull()

            client.requestTokenWithAuthCode(
                oauthMetadata = authorizationService.metadata(),
                url = redirect,
                authorizationServer = authorizationService.publicContext,
                state = authorization.state,
                scope = requestedScope,
                authorizationDetails = setOf(),
            ).getOrThrow()

            receivedPopChallenges shouldBe issuedAttestationChallenges
        }
    }
}

private fun HttpRequestData.parseAcceptHeaderForTokenIntrospection(): ContentType =
    headers[HttpHeaders.Accept]
        ?.let(::parseHeaderValue)
        ?.sortedByDescending { it.quality }
        ?.map { ContentType.parse(it.value) }?.firstOrNull {
            it == ContentType.Application.Json || it == ContentType.Application.IntrospectionJwt
        } ?: throw IllegalArgumentException("Accept header is mandatory to specify answer format")
