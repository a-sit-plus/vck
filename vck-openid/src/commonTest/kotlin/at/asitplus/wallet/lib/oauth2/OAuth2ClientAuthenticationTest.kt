package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
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
            // TODO Need support for nonce/challenge
            val clientAttestationPop = BuildClientAttestationPoPJwt(
                signJwt = signClientAttestationPop,
                clientId = client.clientId,
                audience = AUTHORIZATION_SERVER,
                randomSource = RandomSource.Default
            )

            object {
                val scope = randomString()
                val client = client
                val walletProviderCa = walletProviderCa
                val attesterBackend = attesterBackend
                var server = SimpleAuthorizationService(
                    publicContext = AUTHORIZATION_SERVER,
                    strategy = DummyAuthorizationServiceStrategy(scope),
                    clientAuthenticationService = ClientAuthenticationService(
                        enforceClientAuthentication = true,
                        verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                            trustedIssuers = { setOf(walletProviderCaCert) }
                        ),
                    )
                )
                val clientKey = clientKey
                var clientAttestation = clientAttestation
                val clientAttestationPop = clientAttestationPop
                val signClientAttestationPop = signClientAttestationPop

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
                    clientId = client.clientId,
                    audience = AUTHORIZATION_SERVER,
                    randomSource = RandomSource.Default
                )

                suspend fun par(
                    clientAttestation: JwsCompactTyped<JsonWebToken> = this.clientAttestation,
                    clientAttestationPop: JwsCompactTyped<JsonWebToken> = this.clientAttestationPop,
                ) = server.par(
                    client.createAuthRequestJar(state = uuid4().toString(), scope = scope),
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = clientAttestation,
                        clientAttestationPop = clientAttestationPop,
                    )
                ).getOrThrow()

                suspend fun getToken(state: String, code: String): TokenResponseParameters = server.token(
                    request = client.createTokenRequestParameters(
                        state = state,
                        authorization = OAuth2Client.AuthorizationForToken.Code(code),
                        scope = scope
                    ),
                    httpRequest = RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        dpop = null,
                        clientAttestation = this.clientAttestation,
                        clientAttestationPop = freshPop()
                    )
                ).getOrThrow()

                suspend fun introspect(token: TokenResponseParameters) = server.tokenIntrospection(
                    TokenIntrospectionRequest(token = token.accessToken),
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Get,
                        dpop = null,
                        clientAttestation = this.clientAttestation,
                        clientAttestationPop = freshPop()
                    )
                ).getOrThrow()
            }
        }
    } - {

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
            val parResponse = it.server.par(
                authnRequest,
                RequestInfo(
                    url = "https://example.com/",
                    method = HttpMethod.Post,
                    clientAttestation = it.clientAttestation,
                    clientAttestationPop = it.clientAttestationPop
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
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }
        }

        test("client attestation PoP does not contain iss") {
            it.clientAttestationPop.payload.issuer.shouldBeNull()
        }

        test("client attestation PoP does not contain exp") {
            it.clientAttestationPop.payload.expiration.shouldBeNull()
        }

        test("client attestation PoP uses challenge instead of nonce") {
            val challenge = randomString()
            val pop = BuildClientAttestationPoPJwt(
                signJwt = it.signClientAttestationPop,
                clientId = it.client.clientId,
                audience = "some server",
                nonce = challenge,
                randomSource = RandomSource.Default,
            )

            pop.payload.challenge shouldBe challenge
            pop.payload.nonce.shouldBeNull()
        }

        test("reject client attestation with secret material in cnf jwk") {
            val clientAttestation = BuildClientAttestationJwt(
                signJwt = it.attesterBackend,
                clientId = it.client.clientId,
                clientKey = it.clientKey.jsonWebKey.copy(k = byteArrayOf(1)),
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestation = clientAttestation)
            }
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
                it.clientAttestationPop.payload.copy(
                    issuer = it.client.clientId,
                    expiration = Clock.System.now() + 10.minutes,
                )
            )

            it.par(clientAttestationPop = pop)
        }

        test("reject client attestation PoP with iss of another client") {
            val pop = it.signPop(
                it.clientAttestationPop.payload.copy(issuer = "https://attacker.example")
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject expired client attestation PoP") {
            val pop = it.signPop(
                it.clientAttestationPop.payload.copy(expiration = Clock.System.now() - 1.hours)
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without jti") {
            val pop = it.signPop(it.clientAttestationPop.payload.copy(jwtId = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP for another audience") {
            val pop = it.signPop(
                it.clientAttestationPop.payload.copy(audience = "https://attacker.example")
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without aud") {
            val pop = it.signPop(it.clientAttestationPop.payload.copy(audience = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject stale client attestation PoP") {
            val pop = it.signPop(
                it.clientAttestationPop.payload.copy(issuedAt = Clock.System.now() - 1.hours)
            )

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP without iat") {
            val pop = it.signPop(it.clientAttestationPop.payload.copy(issuedAt = null))

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject client attestation PoP with unsupported algorithm") {
            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = it.clientAttestationPop.withHeaderAlg(JwsAlgorithm.Signature.RS256))
            }
        }

        test("reject client attestation PoP not signed by the cnf key") {
            val pop = SignJwt<JsonWebToken>(EphemeralKeyWithSelfSignedCert(), JwsHeaderNone())(
                JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
                it.clientAttestationPop.payload,
                JsonWebToken.serializer(),
            ).getOrThrow()

            shouldThrow<OAuth2Exception> {
                it.par(clientAttestationPop = pop)
            }
        }

        test("reject replayed client attestation PoP") {
            it.par()

            shouldThrow<OAuth2Exception> {
                it.par()
            }
        }

        test("pushed authorization request with wrong client attestation JWT") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            it.clientAttestation = BuildClientAttestationJwt(
                SignJwt(it.walletProviderCa.issue(), JwsHeaderCertOrJwk()),
                clientId = "wrong client id",
                clientKey = it.clientKey.jsonWebKey
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(
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

        test("pushed authorization request with client attestation JWT of an untrusted wallet provider") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            // the attestation is signed by a certificate of it.walletProviderCa, which is not on this trust list
            it.server = SimpleAuthorizationService(
                publicContext = AUTHORIZATION_SERVER,
                strategy = DummyAuthorizationServiceStrategy(it.scope),
                clientAuthenticationService = ClientAuthenticationService(
                    enforceClientAuthentication = true,
                    verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                        trustedIssuers = { setOf(TestCertificateAuthority().certificate()) }
                    ),
                ),
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(
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

            it.clientAttestation = BuildClientAttestationJwt(
                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                clientId = it.client.clientId,
                clientKey = it.clientKey.jsonWebKey
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(
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

        test("pushed authorization request with unsupported client attestation algorithm") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

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
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            val authnResponse = it.server.authorize(authnRequest as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val token = it.getToken(state, code).apply {
                authorizationDetails.shouldBeNull()
            }

            it.introspect(token)
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }
        }

        test("authorization code flow without client authentication") {
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
            shouldThrow<OAuth2Exception> {
                it.server.token(tokenRequest, null).getOrThrow()
            }
        }
    }
}

private suspend fun JwsCompactTyped<JsonWebToken>.withHeaderAlg(alg: JwsAlgorithm.Signature) =
    JwsCompactTyped<JsonWebToken>(jws.jwsHeader.copy(algorithm = alg), jws.getPayload<JsonWebToken>().getOrThrow()) {
        jws.signature.rawByteArray
    }
