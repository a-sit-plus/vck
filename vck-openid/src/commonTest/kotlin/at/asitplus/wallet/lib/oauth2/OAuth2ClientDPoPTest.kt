package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.buildDPoPHeader
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.ktor.http.HttpMethod

class OAuth2ClientDPoPTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var authorizationServiceStrategy: AuthorizationServiceStrategy
    lateinit var server: SimpleAuthorizationService
    lateinit var clientKey: KeyMaterial
    lateinit var jwsService: JwsService
    val tokenUrl = "https://example.com/token"
    val resourceUrl = "https://example.com/resource"

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        authorizationServiceStrategy = DummyAuthorizationServiceStrategy(user, scope)
        server = SimpleAuthorizationService(
            strategy = authorizationServiceStrategy,
            tokenService = TokenService.jwt(
                nonceService = DefaultNonceService(),
                keyMaterial = EphemeralKeyWithoutCert(),
                issueRefreshTokens = true
            ),
        )
        clientKey = EphemeralKeyWithSelfSignedCert()
        jwsService = DefaultJwsService(DefaultCryptoService(clientKey))
    }

    suspend fun getCode(state: String): String {
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val authnResponse = server.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        return code
    }

    test("authorization code flow with DPoP") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader(tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        val dpopForResource = jwsService.buildDPoPHeader(
            resourceUrl,
            accessToken = token.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        server.tokenVerificationService.validateTokenExtractUser(
            token.toHttpHeaderValue(),
            RequestInfo(
                url = resourceUrl,
                method = HttpMethod.Post,
                dpop = dpopForResource
            )
        )
    }

    test("authorization code flow with DPoP and refresh token") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader(tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
            it.refreshToken.shouldNotBeNull()
        }

        val refreshedAccessToken = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                scope = scope
            ),
            RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader(tokenUrl))
        ).getOrThrow()
        refreshedAccessToken.accessToken shouldNotBe token.accessToken

        val dpopForResource = jwsService.buildDPoPHeader(
            resourceUrl,
            accessToken = refreshedAccessToken.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        server.tokenVerificationService.validateTokenExtractUser(
            refreshedAccessToken.toHttpHeaderValue(),
            RequestInfo(
                url = resourceUrl,
                method = HttpMethod.Post,
                dpop = dpopForResource
            )
        )
    }

    test("authorization code flow with DPoP and wrong URL") {
        val state = uuid4().toString()
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader("https://somethingelse.com/"))
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for token") {
        val state = uuid4().toString()
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                )
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for resource") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader(tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.tokenVerificationService.validateTokenExtractUser(
                token.toHttpHeaderValue(),
                null
            )
        }
    }

    test("authorization code flow with DPoP from other key") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            RequestInfo(tokenUrl, HttpMethod.Post, dpop = jwsService.buildDPoPHeader(tokenUrl))
        ).getOrThrow()

        val wrongJwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert()))
        val dpopForResource = wrongJwsService.buildDPoPHeader(
            resourceUrl,
            accessToken = token.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.tokenVerificationService.validateTokenExtractUser(
                token.toHttpHeaderValue(),
                RequestInfo(
                    url = resourceUrl,
                    method = HttpMethod.Post,
                    dpop = dpopForResource
                )
            )
        }
    }
})