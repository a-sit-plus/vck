package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
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
    lateinit var state: String
    val tokenUrl = "https://example.com/token"
    val resourceUrl = "https://example.com/resource"

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        server = SimpleAuthorizationService(
            strategy = DummyAuthorizationServiceStrategy(scope),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true
            ),
        )
        clientKey = EphemeralKeyWithoutCert()
        signDpop = SignJwt(clientKey, JwsHeaderCertOrJwk())
        state = uuid4().toString()
    }

    suspend fun getCode(state: String): String {
        val authnRequest = client.createAuthRequestJar(
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
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = token.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        val dpopForResource = BuildDPoPHeader(
            signDpop = signDpop,
            url = resourceUrl,
            accessToken = token.accessToken,
            nonce = server.getDpopNonce(),
            randomSource = RandomSource.Default,
        )

        // simulate access to protected resource, i.e. verify access token
        server.userInfo(
            token.toHttpHeaderValue(),
            RequestInfo(
                url = resourceUrl,
                method = HttpMethod.Post,
                dpop = dpopForResource
            )
        ).getOrThrow()
    }

    test("authorization code flow with DPoP and refresh token") {
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
            it.refreshToken.shouldNotBeNull()
        }

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = token.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        val refreshedAccessToken = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    accessToken = token.refreshToken,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow()
        refreshedAccessToken.accessToken shouldNotBe token.accessToken

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = refreshedAccessToken.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        val dpopForResource = BuildDPoPHeader(
            signDpop = signDpop,
            url = resourceUrl,
            accessToken = refreshedAccessToken.accessToken,
            nonce = server.getDpopNonce(),
            randomSource = RandomSource.Default,
        )

        // simulate access to protected resource, i.e. verify access token
        server.userInfo(
            refreshedAccessToken.toHttpHeaderValue(),
            RequestInfo(
                url = resourceUrl,
                method = HttpMethod.Post,
                dpop = dpopForResource
            )
        ).getOrThrow()
    }

    test("authorization code flow with DPoP and refresh token, but wrong key in DPoP proof") {
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
            it.refreshToken.shouldNotBeNull()
        }

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = token.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
        shouldThrow<OAuth2Exception.InvalidDpopProof> {
            server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                    scope = scope
                ),
                httpRequest = RequestInfo(
                    url = tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = wrongSignDpop,
                        url = tokenUrl,
                        accessToken = token.refreshToken,
                        nonce = server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()
        }
    }

    test("authorization code flow with DPoP and wrong URL") {
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                httpRequest = RequestInfo(
                    url = tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = signDpop,
                        url = "https://somethingelse.com/",
                        nonce = server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()
        }
    }

    test("authorization code flow with DPoP and wrong nonce") {
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                httpRequest = RequestInfo(
                    url = tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = signDpop,
                        url = tokenUrl,
                        nonce = server.getDpopNonce()!!.reversed(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for token") {
        val code = getCode(state)

        shouldThrow<OAuth2Exception> {
            server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope
                ),
                httpRequest = null
            ).getOrThrow()
        }
    }

    test("authorization code flow without DPoP for resource") {
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = token.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.userInfo(
                token.toHttpHeaderValue(),
                null
            ).getOrThrow()
        }
    }

    test("authorization code flow with DPoP from other key") {
        val code = getCode(state)

        val token = server.token(
            request = client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            httpRequest = RequestInfo(
                url = tokenUrl,
                method = HttpMethod.Post,
                dpop = BuildDPoPHeader(
                    signDpop = signDpop,
                    url = tokenUrl,
                    nonce = server.getDpopNonce(),
                    randomSource = RandomSource.Default,
                )
            )
        ).getOrThrow()

        server.tokenIntrospection(
            TokenIntrospectionRequest(token = token.accessToken),
            null
        ).getOrThrow().apply {
            active shouldBe true
        }

        val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
        val dpopForResource = BuildDPoPHeader(
            signDpop = wrongSignDpop,
            url = resourceUrl,
            accessToken = token.accessToken,
            nonce = server.getDpopNonce(),
            randomSource = RandomSource.Default,
        )

        // simulate access to protected resource, i.e. verify access token
        shouldThrow<OAuth2Exception> {
            server.userInfo(
                token.toHttpHeaderValue(),
                RequestInfo(
                    url = resourceUrl,
                    method = HttpMethod.Post,
                    dpop = dpopForResource
                )
            ).getOrThrow()
        }
    }
})