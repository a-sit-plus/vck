package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.openid.toOAuth2Error
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

class OAuth2KtorClientTest : FunSpec() {

    lateinit var dpopKeyMaterial: KeyMaterial
    lateinit var clientAuthKeyMaterial: KeyMaterial

    lateinit var mockEngine: MockEngine
    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var client: OAuth2KtorClient

    init {
        val strategy = CredentialAuthorizationServiceStrategy(setOf(EuPidScheme))
        val requestedScope = strategy.validScopes().split(" ").first()
        setup(strategy)

        test("auth code and token") {
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

    private fun setup(strategy: CredentialAuthorizationServiceStrategy) {
        dpopKeyMaterial = EphemeralKeyWithoutCert()
        clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val parEndpointPath = "/par"
        val publicContext = "https://issuer.example.com"
        authorizationService = SimpleAuthorizationService(
            strategy = strategy,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            ),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true
            ),
        )
        mockEngine = MockEngine { request ->
            when {
                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: AuthenticationRequestParameters =
                        requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    authorizationService.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<PushedAuthenticationResponseParameters>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: AuthenticationRequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery<AuthenticationRequestParameters>()
                        else requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.token(params, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<TokenResponseParameters>(it),
                                headers = headers {
                                    append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                                }
                            )
                        },
                        onFailure = { respondOAuth2Error(it) },
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
        client = OAuth2KtorClient(
            engine = mockEngine,
            loadClientAttestationJwt = {
                BuildClientAttestationJwt(
                    SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                    clientId = clientId,
                    issuer = "issuer",
                    clientKey = clientAuthKeyMaterial.jsonWebKey
                ).serialize()
            },
            signClientAttestationPop = SignJwt(clientAuthKeyMaterial, JwsHeaderNone()),
            signDpop = SignJwt(dpopKeyMaterial, JwsHeaderCertOrJwk()),
            dpopAlgorithm = dpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            oAuth2Client = OAuth2Client(clientId = clientId),
            randomSource = RandomSource.Default,
        )
    }

    private fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData = respond(
        vckJsonSerializer.encodeToString(throwable.toOAuth2Error(null)),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            (throwable as? OAuth2Exception.UseDpopNonce)?.dpopNonce
                ?.let { append(HttpHeaders.DPoPNonce, it) }
        },
        status = HttpStatusCode.BadRequest
    ).also { Napier.w("Server error: ${throwable.message}", throwable) }


    private fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
        url = url.toString(),
        method = method,
        dpop = headers["DPoP"],
        clientAttestation = headers["OAuth-Client-Attestation"],
        clientAttestationPop = headers["OAuth-Client-Attestation-PoP"],
    )

    private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
}
