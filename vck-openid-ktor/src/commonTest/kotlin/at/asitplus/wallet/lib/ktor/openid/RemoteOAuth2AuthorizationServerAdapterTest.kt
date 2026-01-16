package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.openid.OpenIdConstants.WellKnownPaths
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.TokenInfo
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headers
import io.ktor.http.headersOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

val RemoteOAuth2AuthorizationServerAdapterTest by testSuite {

    val issuer = "https://issuer.example.com"
    val tokenEndpoint = "$issuer/token"
    val introspectionEndpoint = "$issuer/introspect"
    val userInfoEndpoint = "$issuer/userinfo"

    fun oauthMetadata() = OAuth2AuthorizationServerMetadata(
        issuer = issuer,
        tokenEndpoint = tokenEndpoint,
        introspectionEndpoint = introspectionEndpoint,
        userInfoEndpoint = userInfoEndpoint,
    )

    val tokenVerificationService = object : TokenVerificationService {
        override suspend fun validateRefreshToken(
            refreshToken: String,
            httpRequest: RequestInfo?,
            validatedClientKey: at.asitplus.signum.indispensable.josef.JsonWebKey?,
        ) = refreshToken

        override suspend fun getTokenInfo(tokenOrAuthHeader: String): TokenInfo = TokenInfo(
            token = tokenOrAuthHeader,
            scope = null,
            authorizationDetails = null,
        )

        override suspend fun validateAccessToken(
            tokenOrAuthHeader: String,
            httpRequest: RequestInfo?,
            dpopNonceService: NonceService?,
        ) = catching { }

        override suspend fun extractValidatedClientKey(
            httpRequest: RequestInfo?,
        ) = catching { null }
    }

    test("metadata fallback to openid configuration") {
        var oauthMetadataCalls = 0
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> {
                    oauthMetadataCalls += 1
                    respondError(HttpStatusCode.NotFound)
                }

                request.url.rawSegments.drop(1) == WellKnownPaths.OpenidConfiguration -> respond(
                    vckJsonSerializer.encodeToString(OAuth2AuthorizationServerMetadata.serializer(), oauthMetadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            engine = mockEngine,
            internalTokenVerificationService = tokenVerificationService,
        )

        adapter.metadata().also { metadata ->
            metadata.issuer shouldBe issuer
            metadata.userInfoEndpoint shouldBe userInfoEndpoint
        }
        oauthMetadataCalls shouldBe 1
    }

    test("getTokenInfo handles invalid response") {
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    vckJsonSerializer.encodeToString(OAuth2AuthorizationServerMetadata.serializer(), oauthMetadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.encodedPath.endsWith("/introspect") -> respond(
                    vckJsonSerializer.encodeToString(InvalidToken().toOAuth2Error()),
                    status = HttpStatusCode.BadRequest,
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            engine = mockEngine,
            internalTokenVerificationService = tokenVerificationService,
        )

        val result = adapter.getTokenInfo("Bearer token", null)
        result.isFailure.shouldBeTrue()
        result.exceptionOrNull().shouldNotBeNull().message.shouldContain("Error requesting Token Introspection")
    }

    test("getTokenInfo handles inactive token") {
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    vckJsonSerializer.encodeToString(OAuth2AuthorizationServerMetadata.serializer(), oauthMetadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.encodedPath.endsWith("/introspect") -> respond(
                    vckJsonSerializer.encodeToString(TokenIntrospectionResponse(active = false)),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            engine = mockEngine,
            internalTokenVerificationService = tokenVerificationService,
        )

        shouldThrow<InvalidToken> {
            adapter.getTokenInfo("Bearer token", null).getOrThrow()
        }
    }

    test("getUserInfo retries after dpop nonce challenge") {
        var userInfoCalls = 0
        val userInfoResponse = JsonObject(mapOf("sub" to JsonPrimitive("user")))
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    vckJsonSerializer.encodeToString(OAuth2AuthorizationServerMetadata.serializer(), oauthMetadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.encodedPath.endsWith("/token") -> respond(
                    vckJsonSerializer.encodeToString(
                        TokenResponseParameters(
                            accessToken = "access-token",
                            tokenType = "DPoP",
                            scope = "openid profile",
                        )
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.encodedPath.endsWith("/userinfo") -> {
                    userInfoCalls += 1
                    if (userInfoCalls == 1) {
                        respond(
                            vckJsonSerializer.encodeToString(OAuth2Error(error = USE_DPOP_NONCE)),
                            status = HttpStatusCode.BadRequest,
                            headers = headers {
                                append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                                append(HttpHeaders.DPoPNonce, "nonce-1")
                            }
                        )
                    } else {
                        respond(
                            vckJsonSerializer.encodeToString(userInfoResponse),
                            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        )
                    }
                }

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            engine = mockEngine,
            internalTokenVerificationService = tokenVerificationService,
        )

        adapter.getUserInfo("Bearer wallet-token", null).getOrThrow() shouldBe userInfoResponse
        userInfoCalls shouldBe 2
    }
}
