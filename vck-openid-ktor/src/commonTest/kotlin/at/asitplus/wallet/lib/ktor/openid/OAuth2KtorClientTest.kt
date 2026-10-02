package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
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
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondIncludingDpopNonce
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.toFormParameters
import io.github.aakira.napier.Napier
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
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
        val openId4VciServer: OpenId4VciServer,
        val client: OAuth2KtorClient,
    )

    fun setup(
        strategy: CredentialAuthorizationServiceStrategy,
        requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>?,
        requirePAR: Boolean,
    ): Context {
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val introspectionEndpointPath = "/introspect"
        val parEndpointPath = "/par"
        val challengeEndpointPath = "/challenge"
        val publicContext = "https://issuer.example.com"
        val proofNonceService = DefaultNonceService()
        val authorizationService = SimpleAuthorizationService(
            strategy = strategy,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = AttestationBasedClientAuthenticationService(
                acceptedPopMethods = setOf(ClientAttestationPopMethod.AttestationPopJwt),
                nonceService = proofNonceService,
            ),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true,
                dpopNonceService = proofNonceService,
            ),
            requestObjectSigningAlgorithms = requestObjectSigningAlgorithms,
            requirePushedAuthorizationRequests = requirePAR,
        )
        val openId4VciServer = OpenId4VciServer(
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            authorizationService = authorizationService,
            credentialSchemes = AttributeIndex.schemeSet,
        )
        val mockEngine = MockEngine { request ->
            when {
                request.url.fullPath.startsWith(challengeEndpointPath) -> {
                    val response = authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
                    respond(
                        joseCompliantSerializer.encodeToString(AttestationChallengeResponse.serializer(), response),
                        headers = headers {
                            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            append(HttpHeaders.CacheControl, "no-store")
                        },
                    )
                }

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters =
                        RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                    authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) RequestParametersSerializer.decodeFormParameters(queryParameters)
                        else RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromFormUrlEncoded<TokenRequestParameters>()
                    authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { respondOAuth2Error(it) },
                    )
                }

                request.url.fullPath.startsWith(introspectionEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenIntrospectionRequest =
                        requestBody.decodeFromFormUrlEncoded<TokenIntrospectionRequest>()
                    authorizationService.tokenIntrospection(params, request.toRequestInfo()).fold(
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
            openId4VciServer = openId4VciServer,
            client = OAuth2KtorClient(
                engine = mockEngine,
                loadInstanceAttestation = {
                    catching {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = clientId,
                            clientKey = clientAuthKeyMaterial.jsonWebKey
                        )
                    }
                },
                keyMaterial = clientAuthKeyMaterial,
                dpopKeyMaterial = EphemeralKeyWithoutCert(),
                oAuth2Client = OAuth2Client(clientId = clientId),
                randomSource = RandomSource.Default,
            ),
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
                request = TokenIntrospectionRequest(
                    token = tokenResponse.params.accessToken,
                    tokenTypeHint = tokenResponse.params.tokenType,
                    responseFormat = TokenIntrospectionRequest.ResponseFormat.JWT,
                ),
                popAudience = authorizationService.publicContext,
            ).active shouldBe true
        }
    }

    test("errors of the protocol client are still thrown as the deprecated ktor exception") {
        with(setup(strategy, setOf(JwsAlgorithm.Signature.ES256), requirePAR = false)) {
            val client = OAuth2KtorClient(
                engine = MockEngine { respondOAuth2Error(OAuth2Exception.InvalidGrant("nope")) },
                oAuth2Client = OAuth2Client(),
            )

            @Suppress("DEPRECATION")
            client.requestTokenWithPreAuthorizedCode(
                oauthMetadata = authorizationService.metadata(),
                authorizationServer = authorizationService.publicContext,
                preAuthorizedCode = "code",
                transactionCode = null,
                scope = requestedScope,
                authorizationDetails = setOf(),
            ).exceptionOrNull()
                .shouldBeInstanceOf<at.asitplus.wallet.lib.ktor.openid.HttpErrorResponseException>()
                .apply {
                    response.status shouldBe HttpStatusCode.BadRequest
                    oauth2Error.shouldNotBeNull().error shouldBe OAuth2Exception.InvalidGrant("nope").error
                }
        }
    }
}
