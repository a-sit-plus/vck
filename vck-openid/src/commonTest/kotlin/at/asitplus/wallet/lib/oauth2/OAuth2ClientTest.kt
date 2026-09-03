package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponseJson
import at.asitplus.openid.TokenIntrospectionResponseJwt
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.IntrospectionJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider.user
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val OAuth2ClientTest by matrixSuite {
    fixture {
        object {
            val scope = randomString()
            val client = OAuth2Client()
            val server = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = DummyAuthorizationServiceStrategy(scope),
            )

            fun introspectionRequestInfo(acceptHeader: String) = RequestInfo(
                url = "https://example.com/introspect",
                method = HttpMethod.Post,
                headers = headers { set(HttpHeaders.Accept, acceptHeader) },
            )

            suspend fun introspectJson(token: String) = server.tokenIntrospection(
                TokenIntrospectionRequest(token = token),
                httpRequest = introspectionRequestInfo(ContentType.Application.Json.toString()),
            ).getOrThrow().shouldBeInstanceOf<TokenIntrospectionResponseJson>()
        }
    } - {
        test("process with pre-authorized code") {
            val preAuth = it.server.providePreAuthorizedCode(user)
                .shouldNotBeNull()
            val state = uuid4().toString()
            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow()
            token.authorizationDetails.shouldBeNull()
        }
        test("process with pre-authorized code, can't use it twice") {
            val preAuth = it.server.providePreAuthorizedCode(user)
                .shouldNotBeNull()
            val state = uuid4().toString()
            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
                scope = it.scope
            )
            it.server.token(tokenRequest, null).isSuccess shouldBe true
            it.server.token(tokenRequest, null).isFailure shouldBe true
        }
        test("token request with a scope that is only a substring of the granted scope") {
            val preAuth = it.server.providePreAuthorizedCode(user)
                .shouldNotBeNull()
            // Scopes are space-delimited values, so a substring of a granted scope is not itself granted
            val requestedScope = it.scope.dropLast(1)
            it.scope shouldContain requestedScope
            val tokenRequest = it.client.createTokenRequestParameters(
                state = uuid4().toString(),
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
                scope = requestedScope
            )

            shouldThrow<OAuth2Exception> {
                it.server.token(tokenRequest, null).getOrThrow()
            }
        }
        test("process with pushed authorization request") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequest(
                state = state,
                scope = it.scope,
            )
            val parResponse = it.server.par(authnRequest as RequestParameters).getOrThrow()
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val input = it.client.createAuthRequestAfterPar(parResponse) as RequestParameters
            val authnResponse = it.server.authorize(input) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.introspectJson(token.accessToken).active shouldBe true
        }
        test("token introspection JWT response requires authenticated resource server") {
            shouldThrow<OAuth2Exception.InvalidClient> {
                it.server.tokenIntrospection(
                    TokenIntrospectionRequest(token = "unknown-token"),
                    httpRequest = it.introspectionRequestInfo(ContentType.Application.IntrospectionJwt.toString()),
                ).getOrThrow()
            }
        }
        test("token introspection returns inactive JSON for unknown token") {
            it.introspectJson("unknown-token").active shouldBe false
        }
        listOf(ContentType.Any, ContentType.Application.Any).forEach { mediaRange ->
            test("token introspection uses configured default for media range '$mediaRange'") {
                val server = SimpleAuthorizationService(
                    strategy = DummyAuthorizationServiceStrategy(it.scope),
                    defaultTokenIntrospectionResponseFormat = ContentType.Application.Json,
                )

                server.tokenIntrospection(
                    TokenIntrospectionRequest(token = "unknown-token"),
                    httpRequest = it.introspectionRequestInfo(mediaRange.toString()),
                ).getOrThrow()
                    .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
            }
        }
        test("token introspection uses configured default when Accept header is missing") {
            val server = SimpleAuthorizationService(
                strategy = DummyAuthorizationServiceStrategy(it.scope),
                defaultTokenIntrospectionResponseFormat = ContentType.Application.Json,
            )

            server.tokenIntrospection(
                TokenIntrospectionRequest(token = "unknown-token"),
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
        }
        test("token introspection honors a specific rejection over a wildcard") {
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = "unknown-token"),
                httpRequest = it.introspectionRequestInfo(
                    "${TokenIntrospectionResponseJwt.contentType};q=0, ${ContentType.Any};q=1",
                ),
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
        }
        test("token introspection applies a wildcard rejection to every matching response format") {
            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.server.tokenIntrospection(
                    TokenIntrospectionRequest(token = "unknown-token"),
                    httpRequest = it.introspectionRequestInfo(
                        "${ContentType.Any};q=1, ${ContentType.Application.Any};q=0",
                    ),
                ).getOrThrow()
            }
        }
        test("token introspection compares the effective quality of each response format") {
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = "unknown-token"),
                httpRequest = it.introspectionRequestInfo(
                    "${ContentType.Application.Any};q=1, " +
                            "${TokenIntrospectionResponseJwt.contentType};q=0.5",
                ),
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
        }
        listOf(
            "",
            ContentType.Text.Plain.toString(),
            "${ContentType.Application.Json};q=0",
            "${ContentType.Application.IntrospectionJwt};q=0",
            "${ContentType.Application.Any};q=0, ${ContentType.Any};q=1",
            "${ContentType.Application.IntrospectionJwt};q=0, ${ContentType.Application.Json};q=0, ${ContentType.Any};q=1",
        ).forEach { acceptHeader ->
            test("token introspection rejects unusable Accept header '$acceptHeader'") {
                shouldThrow<OAuth2Exception.InvalidRequest> {
                    it.server.tokenIntrospection(
                        TokenIntrospectionRequest(token = "token"),
                        httpRequest = it.introspectionRequestInfo(acceptHeader),
                    ).getOrThrow()
                }
            }
        }
        test("process with pushed authorization request and JAR") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )
            val parResponse = it.server.par(authnRequest).getOrThrow()
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val input = it.client.createAuthRequestAfterPar(parResponse) as RequestParameters
            val authnResponse = it.server.authorize(input) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.introspectJson(token.accessToken).active shouldBe true
        }
        test("process with authorization code flow, and JAR") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )
            val authnResponse = it.server.authorize(authnRequest as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.introspectJson(token.accessToken).active shouldBe true
        }

        test("process with authorization code flow, front channel") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequest(
                state = state,
                scope = it.scope
            )
            val authnResponse = it.server.authorize(authnRequest as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow()
            token.authorizationDetails.shouldBeNull()
        }

        test("process with authorization code flow, authn request must contain scope from token request") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )
            val authnResponse = it.server.authorize(authnRequest as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope.reversed() // invalid, not in authn request
            )
            shouldThrow<OAuth2Exception> {
                it.server.token(tokenRequest, null).getOrThrow()
            }
        }

        test("process with authorization code flow, no scope in token request") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )
            val authnResponse = it.server.authorize(authnRequest as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = null // already specified in authnrequest
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
                scope.shouldBe(scope)
            }

            it.introspectJson(token.accessToken).active shouldBe true
        }

        /**
         * RFC 8693 token exchange issues a fresh access token for the subject token's user. With bearer tokens the
         * presenting client can not be bound to that token, so anyone who captured it could renew it indefinitely.
         */
        test("token exchange is not supported by default") {
            val token = it.server.token(
                it.client.createTokenRequestParameters(
                    state = uuid4().toString(),
                    authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(
                        it.server.providePreAuthorizedCode(user)
                    ),
                    scope = it.scope,
                ),
                null,
            ).getOrThrow()

            shouldThrow<OAuth2Exception.UnsupportedGrantType> {
                it.server.token(
                    it.client.createTokenRequestParameters(
                        state = uuid4().toString(),
                        authorization = OAuth2Client.AuthorizationForToken.TokenExchange(token.accessToken),
                        resource = it.server.metadata().userInfoEndpoint,
                    ),
                    null,
                ).getOrThrow()
            }
        }

        test("token exchange is not advertised when it is not supported") {
            it.server.metadata().grantTypesSupported.shouldNotBeNull()
                .shouldNotContain("urn:ietf:params:oauth:grant-type:token-exchange")
        }

        test("token exchange can not be enabled for bearer tokens") {
            shouldThrow<IllegalArgumentException> {
                SimpleAuthorizationService(
                    strategy = DummyAuthorizationServiceStrategy(it.scope),
                    tokenService = TokenService.bearer(),
                    supportTokenExchange = true,
                )
            }
        }
    }
}
