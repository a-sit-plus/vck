package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.WellKnownPaths
import at.asitplus.openid.TokenIntrospectionJwtPayload
import at.asitplus.openid.TokenIntrospectionJwtResponse
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.toFormParameters
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrusted
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.oauth2.toHttpResponse
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.CredentialRequestDenied
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.TokenInfo
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock

val RemoteOAuth2AuthorizationServerAdapterTest by matrixSuite {

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
            validatedClientKey: at.asitplus.signum.indispensable.josef.JsonWebKey?
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
            validatedClientKey: JsonWebKey?,
        ): KmmResult<ValidatedAccessToken> =
            catching { ValidatedAccessToken(token = tokenOrAuthHeader) }

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
                    joseCompliantSerializer.encodeToString(
                        OAuth2AuthorizationServerMetadata.serializer(),
                        oauthMetadata()
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            httpClient = HttpClient(mockEngine),
            internalTokenVerificationService = tokenVerificationService,
        )

        adapter.metadata().also { metadata ->
            metadata.issuer shouldBe issuer
            metadata.userInfoEndpoint shouldBe userInfoEndpoint
        }
        oauthMetadataCalls shouldBe 1
    }

    test("getTokenInfo handles invalid response") {
        val expectedError = InvalidToken().toOAuth2Error()
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    joseCompliantSerializer.encodeToString(
                        OAuth2AuthorizationServerMetadata.serializer(),
                        oauthMetadata()
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == introspectionEndpoint -> respond(
                    joseCompliantSerializer.encodeToString(expectedError),
                    status = HttpStatusCode.BadRequest,
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            httpClient = HttpClient(mockEngine),
            internalTokenVerificationService = tokenVerificationService,
        )

        adapter.getTokenInfo("Bearer token", null)
            .exceptionOrNull().shouldNotBeNull()
            .let { it as HttpErrorResponseException }
            .oauth2Error shouldBe expectedError
    }

    test("getTokenInfo handles inactive token") {
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    joseCompliantSerializer.encodeToString(
                        OAuth2AuthorizationServerMetadata.serializer(),
                        oauthMetadata()
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == introspectionEndpoint -> respond(
                    joseCompliantSerializer.encodeToString(TokenIntrospectionResponse(active = false)),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            httpClient = HttpClient(mockEngine),
            internalTokenVerificationService = tokenVerificationService,
        )

        shouldThrow<InvalidToken> {
            adapter.getTokenInfo("Bearer token", null).getOrThrow()
        }
    }

    testSuite("getTokenInfo sends the access token with token_type_hint access_token") {
        listOf("Bearer token", "DPoP token", "token").asData(nameFn = { it }) test { authorizationHeader ->
            var form: Map<String, String>? = null
            val mockEngine = MockEngine { request ->
                when {
                    request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                        joseCompliantSerializer.encodeToString(
                            OAuth2AuthorizationServerMetadata.serializer(),
                            oauthMetadata()
                        ),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )

                    request.url.toString() == introspectionEndpoint -> {
                        form = request.body.toByteArray().decodeToString().toFormParameters()
                        respond(TokenIntrospectionResponse(active = true).toHttpResponse())
                    }

                    else -> respondError(HttpStatusCode.NotFound)
                }
            }

            RemoteOAuth2AuthorizationServerAdapter(
                publicContext = issuer,
                httpClient = HttpClient(mockEngine),
                internalTokenVerificationService = tokenVerificationService,
            ).getTokenInfo(authorizationHeader, null).getOrThrow()

            form shouldBe mapOf("token" to "token", "token_type_hint" to "access_token")
        }
    }

    test("getTokenInfo handles jwt response") {
        val authorizationServerKey = EphemeralKeyWithoutCert()
        var accept: String? = null
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    joseCompliantSerializer.encodeToString(
                        OAuth2AuthorizationServerMetadata.serializer(),
                        oauthMetadata()
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == introspectionEndpoint -> {
                    accept = request.headers[HttpHeaders.Accept]
                    val jwt = SignJwt<TokenIntrospectionJwtPayload>(authorizationServerKey, JwsHeaderNone())(
                        JwsContentTypeConstants.TOKEN_INTROSPECTION_JWT,
                        TokenIntrospectionJwtPayload(
                            issuer = issuer,
                            audience = setOf(OAuth2Client().clientId),
                            issuedAt = Clock.System.now(),
                            tokenIntrospection = TokenIntrospectionResponse(
                                active = true,
                                scope = "scope",
                                confirmationClaim = ConfirmationClaim(jsonWebKeyThumbprint = "thumbprint"),
                            ),
                        ),
                        TokenIntrospectionJwtPayload.serializer()
                    ).getOrThrow()
                    respond(TokenIntrospectionJwtResponse(jwt).toHttpResponse())
                }

                else -> respondError(HttpStatusCode.NotFound)
            }
        }

        val adapter = RemoteOAuth2AuthorizationServerAdapter(
            publicContext = issuer,
            httpClient = HttpClient(mockEngine),
            internalTokenVerificationService = tokenVerificationService,
            verifyTokenIntrospectionJwt = VerifyJwsObjectTrusted(
                trustedKeys = { setOf(authorizationServerKey.jsonWebKey) }
            ),
        )

        val tokenInfo = adapter.getTokenInfo("Bearer token", null).getOrThrow()
        tokenInfo.scope shouldBe "scope"
        tokenInfo.confirmationClaim?.jsonWebKeyThumbprint shouldBe "thumbprint"
        accept shouldBe MediaTypes.Application.TOKEN_INTROSPECTION_JWT
    }

    fun userInfoAdapter(
        introspectionResponse: TokenIntrospectionResponse,
        loadOidcUserInfo: LoadOidcUserInfoFun? = null,
        onIntrospection: (form: Map<String, String>) -> Unit = {},
    ) = RemoteOAuth2AuthorizationServerAdapter(
        publicContext = issuer,
        httpClient = HttpClient(MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == WellKnownPaths.OauthAuthorizationServer -> respond(
                    joseCompliantSerializer.encodeToString(
                        OAuth2AuthorizationServerMetadata.serializer(),
                        oauthMetadata()
                    ),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == introspectionEndpoint -> {
                    onIntrospection(request.body.toByteArray().decodeToString().toFormParameters())
                    respond(introspectionResponse.toHttpResponse())
                }

                else -> respondError(HttpStatusCode.NotFound)
            }
        }),
        internalTokenVerificationService = tokenVerificationService,
        loadOidcUserInfo = loadOidcUserInfo,
    )

    test("getUserInfo returns the user claims of the token introspection response") {
        var form: Map<String, String>? = null
        val adapter = userInfoAdapter(
            introspectionResponse = TokenIntrospectionResponse(
                active = true,
                subject = "user",
                additionalClaims = JsonObject(mapOf("given_name" to JsonPrimitive("Susan"))),
            ),
            onIntrospection = { form = it },
        )

        adapter.getUserInfo("DPoP wallet-token", null).getOrThrow() shouldBe JsonObject(
            mapOf("sub" to JsonPrimitive("user"), "given_name" to JsonPrimitive("Susan"))
        )
        form shouldBe mapOf("token" to "wallet-token", "token_type_hint" to "access_token")
    }

    test("getUserInfo accepts aud as array in the token introspection response") {
        val adapter = userInfoAdapter(
            TokenIntrospectionResponse(
                active = true,
                subject = "user",
                audience = setOf(issuer, "https://other.example.com"),
                additionalClaims = JsonObject(mapOf("given_name" to JsonPrimitive("Susan"))),
            )
        )

        adapter.getUserInfo("DPoP wallet-token", null).getOrThrow() shouldBe JsonObject(
            mapOf("sub" to JsonPrimitive("user"), "given_name" to JsonPrimitive("Susan"))
        )
    }

    test("getUserInfo fails if the response contains user claims without sub") {
        shouldThrow<CredentialRequestDenied> {
            userInfoAdapter(
                TokenIntrospectionResponse(
                    active = true,
                    additionalClaims = JsonObject(mapOf("given_name" to JsonPrimitive("Susan"))),
                )
            ).getUserInfo("DPoP wallet-token", null).getOrThrow()
        }
    }

    test("getUserInfo loads the user info with loadOidcUserInfo instead of reading it from the response") {
        val introspectionResponse = TokenIntrospectionResponse(
            active = true,
            subject = "user",
            additionalClaims = JsonObject(mapOf("given_name" to JsonPrimitive("Remote"))),
        )
        val userInfo = JsonObject(mapOf("sub" to JsonPrimitive("user"), "given_name" to JsonPrimitive("Susan")))
        var input: LoadOidcUserInfoFunInput? = null
        val adapter = userInfoAdapter(
            introspectionResponse = introspectionResponse,
            loadOidcUserInfo = { input = it; KmmResult.success(userInfo) },
        )

        adapter.getUserInfo("DPoP wallet-token", null).getOrThrow() shouldBe userInfo
        input shouldBe LoadOidcUserInfoFunInput(token = "wallet-token", response = introspectionResponse)
    }

    test("getUserInfo fails if the response contains no user claims and loadOidcUserInfo is not set") {
        shouldThrow<CredentialRequestDenied> {
            userInfoAdapter(TokenIntrospectionResponse(active = true, subject = "user"))
                .getUserInfo("DPoP wallet-token", null).getOrThrow()
        }
    }

    test("getUserInfo fails for an inactive token") {
        var loadOidcUserInfoCalled = false
        val adapter = userInfoAdapter(
            introspectionResponse = TokenIntrospectionResponse(active = false),
            loadOidcUserInfo = { loadOidcUserInfoCalled = true; KmmResult.success(JsonObject(emptyMap())) },
        )

        shouldThrow<InvalidToken> {
            adapter.getUserInfo("DPoP wallet-token", null).getOrThrow()
        }
        loadOidcUserInfoCalled shouldBe false
    }
}
