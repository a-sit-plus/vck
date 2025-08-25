package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

class OAuth2ClientDPoPTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var server: SimpleAuthorizationService
    lateinit var clientKey: KeyMaterial
    lateinit var signDpop: SignJwtFun<JsonWebToken>
    val tokenUrl = "https://example.com/token"
    val resourceUrl = "https://example.com/resource"

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        server = SimpleAuthorizationService(
            strategy = DummyAuthorizationServiceStrategy(scope),
            tokenService = TokenService.jwt(
                nonceService = DefaultNonceService(),
                keyMaterial = EphemeralKeyWithoutCert(),
                issueRefreshTokens = true
            ),
        )
        clientKey = EphemeralKeyWithoutCert()
        signDpop = SignJwt(clientKey, JwsHeaderCertOrJwk())
    }

    suspend fun getCode(state: String): String {
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val authnResponse = server.authorize(authnRequest) { catching { user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        return code
    }

    test("authorization code flow with DPoP") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            authorizationHeader = null,
            httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        val dpopForResource = BuildDPoPHeader(
            signDpop,
            url = resourceUrl,
            accessToken = token.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        server.userInfo(
            token.toHttpHeaderValue(),
            null,
            null,
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
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            authorizationHeader = null,
            httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
            it.refreshToken.shouldNotBeNull()
        }

        val refreshedAccessToken = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                scope = scope
            ),
            authorizationHeader = null,
            httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, tokenUrl))
        ).getOrThrow()
        refreshedAccessToken.accessToken shouldNotBe token.accessToken

        val dpopForResource = BuildDPoPHeader(
            signDpop,
            url = resourceUrl,
            accessToken = refreshedAccessToken.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        server.userInfo(
            refreshedAccessToken.toHttpHeaderValue(),
            null,
            null,
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
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                authorizationHeader = null,
                httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, "https://somethingelse.com/"))
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for token") {
        val state = uuid4().toString()
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                authorizationHeader = null,
                httpRequest = null
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for resource") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            authorizationHeader = null,
            httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, tokenUrl))
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.userInfo(
                token.toHttpHeaderValue(),
                null,
                null,
                null
            )
        }
    }

    test("authorization code flow with DPoP from other key") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            authorizationHeader = null,
            httpRequest = RequestInfo(tokenUrl, HttpMethod.Post, dpop = BuildDPoPHeader(signDpop, tokenUrl))
        ).getOrThrow()
        val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
        val dpopForResource = BuildDPoPHeader(
            wrongSignDpop,
            resourceUrl,
            accessToken = token.accessToken
        )

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.userInfo(
                token.toHttpHeaderValue(),
                null,
                null,
                RequestInfo(
                    url = resourceUrl,
                    method = HttpMethod.Post,
                    dpop = dpopForResource
                )
            )
        }
    }
})