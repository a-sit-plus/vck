package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponseJson
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider.user
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/** RFC 8414 issuer identifier of the AS under test, i.e. the required `aud` of client attestation PoP JWTs. */
private const val AUTHORIZATION_SERVER = "https://wallet.a-sit.at/authorization-server"

val OAuth2ClientAuthenticationTest by matrixSuite {

    fixture {
        runBlocking {
            val walletProviderCa = TestCertificateAuthority()
            val walletProviderCaCert = walletProviderCa.certificate()
            val attesterBackend = SignJwt<JsonWebToken>(walletProviderCa.issue(), JwsHeaderCertOrJwk())
            val clientKey = EphemeralKeyWithSelfSignedCert()
            val client = OAuth2Client()
            val clientAttestation = BuildClientAttestationJwt(
                attesterBackend,
                clientId = client.clientId,
                clientKey = clientKey.jsonWebKey
            )

            val signClientAttestationPop: SignJwtFun<JsonWebToken> = SignJwt(clientKey, JwsHeaderNone())
            val scope = randomString()
            val server = SimpleAuthorizationService(
                publicContext = AUTHORIZATION_SERVER,
                strategy = DummyAuthorizationServiceStrategy(scope),
                clientAuthenticationService = AttestationBasedClientAuthenticationService(
                    issuerIdentifier = AUTHORIZATION_SERVER,
                    verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                        trustedIssuers = { setOf(walletProviderCaCert) }
                    ),
                )
            )
            val clientAttestationPop = BuildClientAttestationPoPJwt(
                signJwt = signClientAttestationPop,
                audience = AUTHORIZATION_SERVER,
                randomSource = RandomSource.Default
            )

            val otherClientKey = EphemeralKeyWithSelfSignedCert()

            object {
                val scope = scope
                val client = client
                val server = server
                val clientKey = clientKey
                val clientAttestation = clientAttestation
                val clientAttestationPop = clientAttestationPop
                val signClientAttestationPop = signClientAttestationPop
                val attesterBackend = attesterBackend
                val walletProviderCaCert = walletProviderCaCert

                suspend fun signPop(payload: JsonWebToken) = signClientAttestationPop(
                    type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
                    payload = payload,
                    serializer = JsonWebToken.serializer(),
                ).getOrThrow()

                suspend fun signAttestation(payload: JsonWebToken) = attesterBackend(
                    type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT,
                    payload = payload,
                    serializer = JsonWebToken.serializer(),
                ).getOrThrow()

                /**
                 * A conformant client sends a fresh PoP per request (draft-10 5.1: "Clients MUST generate JWTs
                 * for each target"), so every request in a multi-step flow needs its own `jti`.
                 */
                suspend fun freshPop() = BuildClientAttestationPoPJwt(
                    signJwt = signClientAttestationPop,
                    audience = AUTHORIZATION_SERVER,
                    nonce = server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge,
                    randomSource = RandomSource.Default
                )

                suspend fun authenticationFor(
                    client: OAuth2Client,
                    key: EphemeralKeyWithSelfSignedCert,
                    authorizationService: SimpleAuthorizationService = server,
                ) = RequestInfo(
                    url = "https://example.com/",
                    method = HttpMethod.Post,
                    clientAttestation = BuildClientAttestationJwt(
                        attesterBackend,
                        clientId = client.clientId,
                        clientKey = key.jsonWebKey,
                    ),
                    clientAttestationPop = BuildClientAttestationPoPJwt(
                        signJwt = SignJwt(key, JwsHeaderNone()),
                        audience = AUTHORIZATION_SERVER,
                        nonce = authorizationService.attestationChallenge().getOrThrow()
                            .shouldNotBeNull().attestationChallenge,
                        randomSource = RandomSource.Default,
                    ),
                )

                /** A second wallet instance of the same wallet app: same client_id, different instance key. */
                val otherClientKey = otherClientKey

                @Suppress("DEPRECATION")
                suspend fun par(
                    clientAttestation: JwsCompactTyped<JsonWebToken> = this.clientAttestation,
                    clientAttestationPop: JwsCompactTyped<JsonWebToken>? = null,
                ) = server.par(
                    client.createAuthRequestJar(state = uuid4().toString(), scope = scope),
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = clientAttestation,
                        clientAttestationPop = clientAttestationPop ?: freshPop(),
                    )
                ).getOrThrow()

                /**
                 * PAR + authorize round trip. The default configuration advertises (and now enforces)
                 * `require_pushed_authorization_requests`, so this is the only way to obtain a code.
                 */
                @Suppress("DEPRECATION")
                suspend fun codeViaPar(state: String): String = server.par(
                    client.createAuthRequestJar(state = state, scope = scope),
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = this.clientAttestation,
                        clientAttestationPop = freshPop(),
                    )
                ).getOrThrow()
                    .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
                    .let { server.authorize(client.createAuthRequestAfterPar(it) as RequestParameters) { catching { user } } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                    .params?.code.shouldNotBeNull()

                @Suppress("DEPRECATION")
                suspend fun getToken(state: String, code: String): TokenResponseParameters = server.token(
                    request = client.createTokenRequestParameters(
                        state = state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = scope
                    ),
                    httpRequest = RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = this.clientAttestation,
                        clientAttestationPop = freshPop()
                    )
                ).getOrThrow()

                @Suppress("DEPRECATION")
                suspend fun introspect(token: TokenResponseParameters) = server.tokenIntrospection(
                    TokenIntrospectionRequest(token = token.accessToken),
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Get,
                        clientAttestation = this.clientAttestation,
                        clientAttestationPop = freshPop()
                    )
                ).getOrThrow()
            }
        }
    } - {

        test("reject token request from another wallet instance than the one that pushed the request") {
            // Both instances use the same client_id, so the client_id cross-check in authorize() passes:
            // only the key binding established at the PAR endpoint can catch this
            val state = uuid4().toString()
            @Suppress("DEPRECATION")
            val parResponse = it.server.par(
                it.client.createAuthRequestJar(state = state, scope = it.scope),
                it.authenticationFor(it.client, it.clientKey)
            ).getOrThrow().shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val code = it.server
                .authorize(it.client.createAuthRequestAfterPar(parResponse) as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params?.code.shouldNotBeNull()

            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception.InvalidGrant> {
                it.server.token(
                    request = it.client.createTokenRequestParameters(
                        state = state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = it.scope
                    ),
                    httpRequest = it.authenticationFor(it.client, it.otherClientKey)
                ).getOrThrow()
            }
        }

        test("accept token request from the second wallet instance when it pushed the request itself") {
            // Guards against the test above passing merely because the second instance cannot authenticate
            val state = uuid4().toString()
            @Suppress("DEPRECATION")
            val parResponse = it.server.par(
                it.client.createAuthRequestJar(state = state, scope = it.scope),
                it.authenticationFor(it.client, it.otherClientKey)
            ).getOrThrow().shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val code = it.server
                .authorize(it.client.createAuthRequestAfterPar(parResponse) as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params?.code.shouldNotBeNull()

            @Suppress("DEPRECATION")
            it.server.token(
                request = it.client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope
                ),
                httpRequest = it.authenticationFor(it.client, it.otherClientKey)
            ).getOrThrow().accessToken.shouldNotBeNull()
        }

        test("pushed authorization request") {
            it.clientAttestation.payload.issuer.shouldBeNull()
            it.clientAttestation.payload.walletVersion.shouldNotBeNull()
            it.clientAttestation.payload.walletSolutionCertificationInformation.shouldNotBeNull()
            it.clientAttestation.payload.clientStatus.shouldNotBeNull()

            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            @Suppress("DEPRECATION")
            val parResponse = it.server.par(
                authnRequest,
                RequestInfo(
                    url = "https://example.com/",
                    method = HttpMethod.Post,
                    clientAttestation = it.clientAttestation,
                    clientAttestationPop = it.freshPop()
                )
            ).getOrThrow()
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val authnResponse = it.server
                .authorize(it.client.createAuthRequestAfterPar(parResponse) as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val token = it.getToken(state, code).apply {
                authorizationDetails.shouldBeNull()
            }
            it.introspect(token)
                .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
                .apply { active shouldBe true }
        }

        test("authorization code is bound to the client id") {
            val state = uuid4().toString()
            val code = it.codeViaPar(state)
            val legitimateRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope,
            )
            val attacker = OAuth2Client(clientId = "https://attacker.example/app")
            val attackerKey = EphemeralKeyWithSelfSignedCert()

            shouldThrow<OAuth2Exception> {
                it.server.token(
                    legitimateRequest.copy(clientId = attacker.clientId),
                    it.authenticationFor(attacker, attackerKey),
                ).getOrThrow()
            }
        }

        test("refresh token is bound when a client first authenticates at the token endpoint") {
            val server = SimpleAuthorizationService(
                publicContext = AUTHORIZATION_SERVER,
                strategy = DummyAuthorizationServiceStrategy(it.scope),
                tokenService = TokenService.bearer(issueRefreshTokens = true),
                clientAuthenticationService = AttestationBasedClientAuthenticationService(
                    issuerIdentifier = AUTHORIZATION_SERVER,
                    verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                        trustedIssuers = { setOf(it.walletProviderCaCert) },
                    ),
                ),
            )
            val preAuthorizedCode = server.providePreAuthorizedCode(user)
            val refreshToken = server.token(
                it.client.createTokenRequestParameters(
                    authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuthorizedCode),
                    scope = it.scope,
                ),
                it.authenticationFor(it.client, it.clientKey, server),
            ).getOrThrow().refreshToken.shouldNotBeNull()
            val attacker = OAuth2Client()
            val attackerKey = EphemeralKeyWithSelfSignedCert()

            shouldThrow<OAuth2Exception> {
                server.token(
                    attacker.createTokenRequestParameters(
                        authorization = OAuth2Client.AuthorizationForToken.RefreshToken(refreshToken),
                        scope = it.scope,
                    ),
                    it.authenticationFor(attacker, attackerKey, server),
                ).getOrThrow()
            }
        }

        test("client attestation PoP does not contain iss") {
            it.clientAttestationPop.payload.issuer.shouldBeNull()
        }

        test("client attestation PoP does not contain exp") {
            it.clientAttestationPop.payload.expiration.shouldBeNull()
        }

        test("client attestation PoP uses challenge and nonce") {
            val challenge = it.server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge
            val pop = BuildClientAttestationPoPJwt(
                signJwt = it.signClientAttestationPop,
                audience = "some server",
                nonce = challenge,
                randomSource = RandomSource.Default,
            )

            pop.payload.challenge shouldBe challenge
            pop.payload.nonce shouldBe challenge
        }

        test("reject client attestation without cnf") {
            val clientAttestation = it.signAttestation(it.clientAttestation.payload.copy(confirmationClaim = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestation = clientAttestation)
            }
        }

        test("accept client attestation with iss, removed in draft 8 but tolerated") {
            val clientAttestation = it.signAttestation(
                it.clientAttestation.payload.copy(issuer = "https://attester.example")
            )

            it.par(clientAttestation = clientAttestation)
        }

        test("accept client attestation PoP with iss and exp, removed in draft 8 and 6 but tolerated") {
            val pop = it.signPop(
                it.freshPop().payload.copy(
                    issuer = it.client.clientId,
                    expiration = Clock.System.now() + 10.minutes,
                )
            )

            it.par(clientAttestationPop = pop)
        }

        test("reject client attestation PoP with iss of another client") {
            val pop = it.signPop(
                it.freshPop().payload.copy(issuer = "https://attacker.example")
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject expired client attestation PoP") {
            val pop = it.signPop(
                it.freshPop().payload.copy(expiration = Clock.System.now() - 1.hours)
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without jti") {
            val pop = it.signPop(it.freshPop().payload.copy(jwtId = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP for another audience") {
            val pop = it.signPop(
                it.freshPop().payload.copy(audience = "https://attacker.example")
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without aud") {
            val pop = it.signPop(it.freshPop().payload.copy(audience = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject stale client attestation PoP") {
            val pop = it.signPop(
                it.freshPop().payload.copy(issuedAt = Clock.System.now() - 1.hours)
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without iat") {
            val pop = it.signPop(it.freshPop().payload.copy(issuedAt = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP with unsupported algorithm") {
            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = it.freshPop().withHeaderAlg(JwsAlgorithm.Signature.RS256))
            }
        }

        test("reject client attestation PoP not signed by the cnf key") {
            val payload = it.freshPop().payload
            val pop = SignJwt<JsonWebToken>(EphemeralKeyWithSelfSignedCert(), JwsHeaderNone())(
                JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
                payload,
                JsonWebToken.serializer(),
            ).getOrThrow()

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject replayed client attestation PoP") {
            val pop = it.freshPop()
            it.par(clientAttestationPop = pop)

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("pushed authorization request with wrong client attestation JWT") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            val clientAttestation = BuildClientAttestationJwt(
                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                clientId = "wrong client id",
                clientKey = it.clientKey.jsonWebKey
            )

            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception> {
                it.server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = clientAttestation,
                        clientAttestationPop = it.clientAttestationPop
                    )
                ).getOrThrow()
            }
        }

        test("pushed authorization request with client attestation JWT of an untrusted wallet provider") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            // the attestation is signed by a certificate of it.walletProviderCa, which is not on this trust list
            val server = SimpleAuthorizationService(
                publicContext = AUTHORIZATION_SERVER,
                strategy = DummyAuthorizationServiceStrategy(it.scope),
                clientAuthenticationService = AttestationBasedClientAuthenticationService(

                    verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                        trustedIssuers = { setOf(TestCertificateAuthority().certificate()) }
                    ),
                ),
            )

            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception> {
                server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = it.clientAttestation,
                        clientAttestationPop = it.clientAttestationPop
                    )
                ).getOrThrow()
            }
        }

        test("pushed authorization request with self-signed client attestation JWT") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            val clientAttestation = BuildClientAttestationJwt(
                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                clientId = it.client.clientId,
                clientKey = it.clientKey.jsonWebKey
            )

            shouldThrow<OAuth2Exception> {
                @Suppress("DEPRECATION")
                it.server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = clientAttestation,
                        clientAttestationPop = it.clientAttestationPop
                    )
                ).getOrThrow()
            }
        }

        test("pushed authorization request with unsupported client attestation algorithm") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            @Suppress("DEPRECATION")
            shouldThrow<OAuth2Exception> {
                it.server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = it.clientAttestation.withHeaderAlg(JwsAlgorithm.Signature.RS256),
                        clientAttestationPop = it.clientAttestationPop
                    )
                ).getOrThrow()
            }
        }

        test("pushed authorization request without client authentication") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(authnRequest).getOrThrow()
            }
        }

        test("authorization code flow and client authentication") {
            val state = uuid4().toString()
            val code = it.codeViaPar(state)

            val token = it.getToken(state, code).apply {
                authorizationDetails.shouldBeNull()
            }

            it.introspect(token)
                .shouldBeInstanceOf<TokenIntrospectionResponseJson>()
                .apply { active shouldBe true }
        }

        test("authorization code flow without client authentication") {
            val state = uuid4().toString()
            val code = it.codeViaPar(state)

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            shouldThrow<OAuth2Exception> {
                it.server.token(tokenRequest, null).getOrThrow()
            }
        }

        /**
         * RFC 9126 4.: when the AS advertises `require_pushed_authorization_requests`, it MUST reject
         * authorization requests that have not been pushed. Otherwise a client can opt out of the client
         * binding established at the PAR endpoint by simply not using it.
         */
        test("reject a plain authorization request when pushed authorization requests are required") {
            val request = it.client.createAuthRequest(state = uuid4().toString(), scope = it.scope)
            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.server.authorize(request as RequestParameters) { catching { user } }.getOrThrow()
            }
        }

        test("reject a request object by value when pushed authorization requests are required") {
            val request = it.client.createAuthRequestJar(state = uuid4().toString(), scope = it.scope)
            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.server.authorize(request as RequestParameters) { catching { user } }.getOrThrow()
            }
        }

        /** RFC 7636 and OID4VC HAIP require PKCE with S256, so a request without a challenge must not pass. */
        test("reject an authorization request without code_challenge") {
            val request = it.client.createAuthRequest(state = uuid4().toString(), scope = it.scope)
                .copy(codeChallenge = null)
            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.server.par(request, it.authenticationFor(it.client, it.clientKey)).getOrThrow()
            }
        }

        test("reject an authorization request with a code_challenge_method other than S256") {
            val request = it.client.createAuthRequest(state = uuid4().toString(), scope = it.scope)
                .copy(codeChallengeMethod = "plain")
            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.server.par(request, it.authenticationFor(it.client, it.clientKey)).getOrThrow()
            }
        }

        test("reject a token request that omits the code_verifier") {
            val state = uuid4().toString()
            val code = it.codeViaPar(state)
            shouldThrow<OAuth2Exception.InvalidGrant> {
                it.server.token(
                    it.client.createTokenRequestParameters(
                        state = state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = it.scope,
                    ).copy(codeVerifier = null),
                    it.authenticationFor(it.client, it.clientKey),
                ).getOrThrow()
                // assert on the reason, so this does not silently pass on a client binding mismatch
            }.description.shouldNotBeNull() shouldContain "code verifier"
        }

        test("advertise S256 as the only supported code_challenge_method") {
            it.server.metadata().codeChallengeMethodsSupported shouldBe setOf("S256")
        }
    }
}

private suspend fun JwsCompactTyped<JsonWebToken>.withHeaderAlg(alg: JwsAlgorithm.Signature) =
    JwsCompactTyped<JsonWebToken>(jws.jwsHeader.copy(algorithm = alg), jws.getPayload<JsonWebToken>().getOrThrow()) {
        jws.signature.rawByteArray
    }
