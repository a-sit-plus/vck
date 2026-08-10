package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
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
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import io.github.aakira.napier.Napier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
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
    )

    fun setup(
        strategy: CredentialAuthorizationServiceStrategy,
        requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>?,
        requirePAR: Boolean,
        captureAttestationInput: ((OAuth2KtorClient.LoadInstanceAttestationInput) -> Unit)? = null,
    ): Context {
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val introspectionEndpointPath = "/introspect"
        val parEndpointPath = "/par"
        val publicContext = "https://issuer.example.com"
        val authorizationService = SimpleAuthorizationService(
            strategy = strategy,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = AttestationBasedClientAuthenticationService(),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true
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
        val mockEngine = MockEngine { request ->
            when {
                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
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
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { respondOAuth2Error(it) },
                    )
                }

                request.url.fullPath.startsWith(introspectionEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenIntrospectionRequest =
                        requestBody.decodeFromPostBody<TokenIntrospectionRequest>()
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
                oAuth2Client = OAuth2Client(clientId = clientId),
                randomSource = RandomSource.Default,
            )
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
                    useDpop = false,
                    authorizationServer = authorizationService.publicContext,
                    oauthMetadata = authorizationService.metadata(),
                )
            }.message shouldContain "does not match"
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
}
