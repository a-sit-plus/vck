package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val OAuth2ClientDPoPTest by testSuite {
    withFixtureGenerator {
        object {
            val tokenUrl = "https://example.com/token"
            val resourceUrl = "https://example.com/resource"
            val scope = randomString()
            val client = OAuth2Client()
            val user = OidcUserInfoExtended(OidcUserInfo(randomString()))
            val server = SimpleAuthorizationService(
                strategy = DummyAuthorizationServiceStrategy(scope),
                tokenService = TokenService.jwt(
                    issueRefreshTokens = true
                ),
            )
            val clientKey = EphemeralKeyWithoutCert()
            val signDpop = SignJwt<JsonWebToken>(clientKey, JwsHeaderCertOrJwk())
            val state = uuid4().toString()

            suspend fun getCode(state: String): String {
                val authnRequest = client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                )
                val authnResponse = server.authorize(authnRequest as RequestParameters) { catching { user } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                return code
            }
        }
    } - {
        test("authorization code flow with DPoP") {
            val code = it.getCode(it.state)

            val token = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow().also {
                it.tokenType shouldBe TOKEN_TYPE_DPOP
            }

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            val dpopForResource = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = it.resourceUrl,
                accessToken = token.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            // simulate access to protected resource, i.e. verify access token
            it.server.userInfo(
                token.toHttpHeaderValue(),
                RequestInfo(
                    url = it.resourceUrl,
                    method = HttpMethod.Post,
                    dpop = dpopForResource
                )
            ).getOrThrow()

        }

        test("authorization code flow with DPoP and refresh token") {
            val code = it.getCode(it.state)

            val token = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow().also {
                it.tokenType shouldBe TOKEN_TYPE_DPOP
                it.refreshToken.shouldNotBeNull()
            }

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            val refreshedAccessToken = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        accessToken = token.refreshToken,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()
            refreshedAccessToken.accessToken shouldNotBe token.accessToken

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = refreshedAccessToken.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            val dpopForResource = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = it.resourceUrl,
                accessToken = refreshedAccessToken.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            // simulate access to protected resource, i.e. verify access token
            it.server.userInfo(
                refreshedAccessToken.toHttpHeaderValue(),
                RequestInfo(
                    url = it.resourceUrl,
                    method = HttpMethod.Post,
                    dpop = dpopForResource
                )
            ).getOrThrow()
        }

        test("authorization code flow with DPoP and refresh token, but wrong key in DPoP proof") {
            val code = it.getCode(it.state)

            val token = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow().also {
                it.tokenType shouldBe TOKEN_TYPE_DPOP
                it.refreshToken.shouldNotBeNull()
            }

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.RefreshToken(token.refreshToken!!),
                        scope = it.scope
                    ),
                    httpRequest = RequestInfo(
                        url = it.tokenUrl,
                        method = HttpMethod.Post,
                        dpop = BuildDPoPHeader(
                            signDpop = wrongSignDpop,
                            url = it.tokenUrl,
                            accessToken = token.refreshToken,
                            nonce = it.server.getDpopNonce(),
                            randomSource = RandomSource.Default,
                        )
                    )
                ).getOrThrow()
            }
        }

        test("authorization code flow with DPoP and wrong URL") {
            val code = it.getCode(it.state)

            shouldThrow<OAuth2Exception> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = it.scope
                    ),
                    httpRequest = RequestInfo(
                        url = it.tokenUrl,
                        method = HttpMethod.Post,
                        dpop = BuildDPoPHeader(
                            signDpop = it.signDpop,
                            url = "https://somethingelse.com/",
                            nonce = it.server.getDpopNonce(),
                            randomSource = RandomSource.Default,
                        )
                    )
                ).getOrThrow()
            }
        }

        test("authorization code flow with DPoP and wrong nonce") {
            val code = it.getCode(it.state)

            shouldThrow<OAuth2Exception> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = it.scope
                    ),
                    httpRequest = RequestInfo(
                        url = it.tokenUrl,
                        method = HttpMethod.Post,
                        dpop = BuildDPoPHeader(
                            signDpop = it.signDpop,
                            url = it.tokenUrl,
                            nonce = it.server.getDpopNonce()!!.reversed(),
                            randomSource = RandomSource.Default,
                        )
                    )
                ).getOrThrow()
            }
        }

        test("authorization code flow without DPoP for token") {
            val code = it.getCode(it.state)

            shouldThrow<OAuth2Exception> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = it.scope
                    ),
                    httpRequest = null
                ).getOrThrow()
            }
        }

        test("authorization code flow without DPoP for resource") {
            val code = it.getCode(it.state)

            val token = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow().also {
                it.tokenType shouldBe TOKEN_TYPE_DPOP
            }

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            // simulate access to protected resource, i.e. verify access token
            shouldThrow<OAuth2Exception> {
                it.server.userInfo(
                    token.toHttpHeaderValue(),
                    null
                ).getOrThrow()
            }
        }

        test("authorization code flow with DPoP from other key") {
            val code = it.getCode(it.state)

            val token = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }

            val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
            val dpopForResource = BuildDPoPHeader(
                signDpop = wrongSignDpop,
                url = it.resourceUrl,
                accessToken = token.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            // simulate access to protected resource, i.e. verify access token
            shouldThrow<OAuth2Exception> {
                it.server.userInfo(
                    token.toHttpHeaderValue(),
                    RequestInfo(
                        url = it.resourceUrl,
                        method = HttpMethod.Post,
                        dpop = dpopForResource
                    )
                ).getOrThrow()
            }
        }
    }
}