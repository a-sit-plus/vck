package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

val OAuth2ClientDPoPTest by matrixSuite {
    fixture {
        object {
            val tokenUrl = "https://example.com/token"
            val resourceUrl = "https://example.com/resource"
            val scope = randomString()
            val client = OAuth2Client()
            val user = OidcUserInfoExtended(OidcUserInfo(randomString()))
            val issuerKey = EphemeralKeyWithoutCert()
            val tokenService = TokenService.jwt(issueRefreshTokens = true, keyMaterial = issuerKey)
            val server = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = DummyAuthorizationServiceStrategy(scope),
                tokenService = tokenService,
                supportTokenExchange = true,
            )
            val clientKey = EphemeralKeyWithoutCert()
            val signDpop = SignJwt<JsonWebToken>(clientKey, JwsHeaderCertOrJwk())
            val state = uuid4().toString()

            suspend fun dpopProof(
                transform: (JsonWebToken) -> JsonWebToken = { it },
            ) = BuildDPoPHeader(
                signDpop = signDpop,
                url = tokenUrl,
                nonce = server.getDpopNonce(),
                randomSource = RandomSource.Default,
            ).let {
                signDpop(
                    JwsContentTypeConstants.DPOP_JWT,
                    transform(it.payload),
                    JsonWebToken.serializer(),
                ).getOrThrow()
            }

            @Suppress("DEPRECATION")
            suspend fun validateDpop(
                dpop: JwsCompactTyped<JsonWebToken>,
                url: String = tokenUrl,
                method: HttpMethod = HttpMethod.Post,
            ) = tokenService.verification.extractValidatedClientKey(
                RequestInfo(url = url, method = method, dpop = dpop)
            ).getOrThrow()

            /** Signs an access token as the authorization server itself would, to forge token contents. */
            suspend fun signAccessToken(payload: OpenId4VciAccessToken, key: KeyMaterial = issuerKey) =
                SignJwt<OpenId4VciAccessToken>(key, JwsHeaderCertOrJwk())(
                    JwsContentTypeConstants.OID4VCI_AT_JWT,
                    payload,
                    OpenId4VciAccessToken.serializer(),
                ).getOrThrow()

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

            @Suppress("DEPRECATION")
            suspend fun getAccessToken(): TokenResponseParameters = server.token(
                request = client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(getCode(state)),
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
        }
    } - {
        test("getUserInfo returns user info for a valid access token") {
            val token = it.getAccessToken()

            @Suppress("DEPRECATION")
            it.server.getUserInfo(
                token.toHttpHeaderValue(),
                RequestInfo(
                    url = it.resourceUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.resourceUrl,
                        accessToken = token.accessToken,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    )
                )
            ).getOrThrow()
        }

        test("getUserInfo rejects an access token with an invalid signature") {
            // The jti is readable from any observed access token, so user info must not be reachable by
            // replaying it in a token this authorization server did not sign
            val payload = JwsCompactTyped<OpenId4VciAccessToken>(it.getAccessToken().accessToken).payload
            val forged = it.signAccessToken(payload, key = EphemeralKeyWithoutCert())

            shouldThrow<OAuth2Exception.InvalidToken> {
                it.server.getUserInfo("${OpenIdConstants.TOKEN_PREFIX_DPOP}$forged", null).getOrThrow()
            }
        }

        test("getUserInfo rejects an expired access token") {
            val payload = JwsCompactTyped<OpenId4VciAccessToken>(it.getAccessToken().accessToken).payload
            val expired = it.signAccessToken(payload.copy(expiration = Clock.System.now() - 1.hours))

            shouldThrow<OAuth2Exception.InvalidToken> {
                it.server.getUserInfo("${OpenIdConstants.TOKEN_PREFIX_DPOP}$expired", null).getOrThrow()
            }
        }

        test("authorization code flow with DPoP") {
            val code = it.getCode(it.state)
            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

            val dpopForResource = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = it.resourceUrl,
                accessToken = token.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            // simulate access to protected resource, i.e. verify access token
            @Suppress("DEPRECATION")
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

            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

            val dpopForResource = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = it.resourceUrl,
                accessToken = refreshedAccessToken.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            @Suppress("DEPRECATION")
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

            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

            val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
            @Suppress("DEPRECATION")
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

        test("reject DPoP proof with wrong URL without consuming nonce") {
            val nonce = it.server.getDpopNonce()
            val wrongProof = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = "https://somethingelse.com/",
                nonce = nonce,
                randomSource = RandomSource.Default,
            )

            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(wrongProof)
            }

            it.validateDpop(
                BuildDPoPHeader(
                    signDpop = it.signDpop,
                    url = it.tokenUrl,
                    nonce = nonce,
                    randomSource = RandomSource.Default,
                )
            ).shouldNotBeNull()
        }

        test("reject DPoP proof with wrong HTTP method") {
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(it.dpopProof { proof -> proof.copy(httpMethod = "GET") })
            }
        }

        test("reject DPoP proof without jti") {
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(it.dpopProof { proof -> proof.copy(jwtId = null) })
            }
        }

        test("reject DPoP proof without iat") {
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(it.dpopProof { proof -> proof.copy(issuedAt = null) })
            }
        }

        test("reject DPoP proof with iat in the future") {
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(it.dpopProof { proof -> proof.copy(issuedAt = Clock.System.now() + 1.hours) })
            }
        }

        test("reject DPoP proof issued too long ago") {
            // RFC 9449 4.3: the creation time must be within an acceptable window, so a proof stays replayable
            // for as long as its nonce lives without a lower bound on iat
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(it.dpopProof { proof -> proof.copy(issuedAt = Clock.System.now() - 24.hours) })
            }
        }

        test("reject DPoP proof with an algorithm the AS does not advertise") {
            // RFC 9449 4.3: alg must be an asymmetric algorithm the server supports, i.e. one of the algorithms
            // published as dpop_signing_alg_values_supported
            val es384Only = TokenService.jwt(
                keyMaterial = it.issuerKey,
                verificationAlgorithms = setOf(JwsAlgorithm.Signature.ES384),
            )
            es384Only.dpopSigningAlgValuesSupportedStrings shouldBe setOf(JwsAlgorithm.Signature.ES384.identifier)

            val es256Proof = BuildDPoPHeader(
                signDpop = it.signDpop,
                url = it.tokenUrl,
                nonce = es384Only.dpopNonce(),
                randomSource = RandomSource.Default,
            )
            es256Proof.jws.jwsHeader.algorithm shouldBe JwsAlgorithm.Signature.ES256

            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                es384Only.verification.extractValidatedClientKey(
                    RequestInfo(url = it.tokenUrl, method = HttpMethod.Post, dpop = es256Proof)
                ).getOrThrow()
            }
        }

        test("reject duplicate DPoP headers") {
            // draft-10 7.3 and RFC 9449 4.2: exactly one proof, so a second header cannot be smuggled past the
            // parsed single-value accessor
            val proof = it.dpopProof()
            val duplicated = RequestInfo(
                url = it.tokenUrl,
                method = HttpMethod.Post,
                headers = headers {
                    append(HttpHeaders.DPoP, proof.toString())
                    append(HttpHeaders.DPoP, proof.toString())
                },
            )

            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.tokenService.verification.extractValidatedClientKey(duplicated).getOrThrow()
            }
        }

        test("token exchange consumes the DPoP nonce only once") {
            val token = it.getAccessToken()
            val resource = it.server.metadata().userInfoEndpoint.shouldNotBeNull()

            @Suppress("DEPRECATION")
            val exchanged = it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.TokenExchange(token.accessToken),
                    resource = resource,
                ),
                httpRequest = RequestInfo(
                    url = it.tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = it.signDpop,
                        url = it.tokenUrl,
                        accessToken = token.accessToken,
                        nonce = it.server.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    ),
                ),
            ).getOrThrow()

            exchanged.accessToken shouldNotBe token.accessToken
        }

        test("token exchange rejects a subject token bound to another key") {
            val token = it.getAccessToken()
            val resource = it.server.metadata().userInfoEndpoint.shouldNotBeNull()
            val otherKey = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())

            // Guards the test above against passing because the ath and cnf.jkt checks were dropped along with
            // the second nonce check
            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = it.state,
                        authorization = OAuth2Client.AuthorizationForToken.TokenExchange(token.accessToken),
                        resource = resource,
                    ),
                    httpRequest = RequestInfo(
                        url = it.tokenUrl,
                        method = HttpMethod.Post,
                        dpop = BuildDPoPHeader(
                            signDpop = otherKey,
                            url = it.tokenUrl,
                            accessToken = token.accessToken,
                            nonce = it.server.getDpopNonce(),
                            randomSource = RandomSource.Default,
                        ),
                    ),
                ).getOrThrow()
            }
        }

        test("reject DPoP proof without public JWK") {
            val proof = BuildDPoPHeader(
                signDpop = SignJwt(it.clientKey, JwsHeaderNone()),
                url = it.tokenUrl,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            shouldThrow<OAuth2Exception.InvalidDpopProof> {
                it.validateDpop(proof)
            }
        }

        test("authorization code flow with DPoP and wrong nonce") {
            val code = it.getCode(it.state)
            @Suppress("DEPRECATION")
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
            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

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
            @Suppress("DEPRECATION")
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
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }

            val wrongSignDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
            val dpopForResource = BuildDPoPHeader(
                signDpop = wrongSignDpop,
                url = it.resourceUrl,
                accessToken = token.accessToken,
                nonce = it.server.getDpopNonce(),
                randomSource = RandomSource.Default,
            )

            // simulate access to protected resource, i.e. verify access token
            @Suppress("DEPRECATION")
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
