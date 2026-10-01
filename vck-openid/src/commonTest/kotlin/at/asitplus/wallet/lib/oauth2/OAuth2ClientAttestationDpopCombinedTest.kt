package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider.user
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking

/** RFC 8414 issuer identifier of the AS under test. */
private const val AUTHORIZATION_SERVER = "https://wallet.a-sit.at/authorization-server"

/**
 * DPoP combined mode, i.e. one DPoP proof serving as the Client Attestation PoP, from sections 5.2 and 7.3 of
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html).
 */
val OAuth2ClientAttestationDpopCombinedTest by matrixSuite {

    fixture {
        runBlocking {
            val walletProviderCa = TestCertificateAuthority()
            val walletProviderCaCert = walletProviderCa.certificate
            val attesterBackend = SignJwt<JsonWebToken>(walletProviderCa.issue(), JwsHeaderCertOrJwk())
            val client = OAuth2Client()
            val scope = randomString()

            /** The attested key is also the DPoP key: combined mode has only one key. */
            val clientKey: KeyMaterial = EphemeralKeyWithoutCert()
            val clientAttestation = BuildClientAttestationJwt(
                attesterBackend,
                clientId = client.clientId,
                clientKey = clientKey.jsonWebKey,
            )

            /**
             * The attestation challenge is carried in the DPoP proof's `nonce`, so the challenge store and the
             * DPoP nonce store must be the same instance.
             */
            fun serverWith(vararg popMethods: ClientAttestationPopMethod): SimpleAuthorizationService {
                val proofNonceService = DefaultNonceService()
                return SimpleAuthorizationService(
                    publicContext = AUTHORIZATION_SERVER,
                    strategy = DummyAuthorizationServiceStrategy(scope),
                    tokenService = TokenService.jwt(dpopNonceService = proofNonceService),
                    clientAuthenticationService = AttestationBasedClientAuthenticationService(
                        issuerIdentifier = AUTHORIZATION_SERVER,
                        verifyJwsObject = VerifyJwsObjectTrustedCertificate(
                            trustedIssuers = { setOf(walletProviderCaCert) }
                        ),
                        nonceService = proofNonceService,
                        acceptedPopMethods = popMethods.toSet(),
                    ),
                )
            }

            object {
                val scope = scope
                val client = client
                val clientKey = clientKey
                val clientAttestation = clientAttestation
                val attesterBackend = attesterBackend
                val combinedOnly = serverWith(ClientAttestationPopMethod.DpopCombined)
                val normalOnly = serverWith(ClientAttestationPopMethod.AttestationPopJwt)
                val bothModes = serverWith(
                    ClientAttestationPopMethod.AttestationPopJwt,
                    ClientAttestationPopMethod.DpopCombined,
                )

                /**
                 * A request carrying both proofs, which no conformant client sends: draft-10 7 has the AS advertise
                 * the method it accepts, so the client picks one.
                 */
                suspend fun bothProofsRequest(
                    server: SimpleAuthorizationService,
                    url: String = "https://example.com/",
                ): RequestInfo {
                    val pop = BuildClientAttestationPoPJwt(
                        signJwt = SignJwt(clientKey, JwsHeaderNone()),
                        audience = AUTHORIZATION_SERVER,
                        nonce = server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge,
                        randomSource = RandomSource.Default,
                    )
                    val dpop = BuildDPoPHeader(
                        signDpop = SignJwt(clientKey, JwsHeaderJwk()),
                        url = url,
                        nonce = server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge,
                        randomSource = RandomSource.Default,
                    )
                    return RequestInfo(
                        url = url,
                        method = HttpMethod.Post,
                        headers = headers {
                            append(HttpHeaders.OAuthClientAttestation, clientAttestation.toString())
                            append(HttpHeaders.OAuthClientAttestationPop, pop.toString())
                            append(HttpHeaders.DPoP, dpop.toString())
                        },
                    )
                }

                /** A request in DPoP combined mode: attestation plus one DPoP proof, and no dedicated PoP. */
                suspend fun combinedRequest(
                    server: SimpleAuthorizationService = combinedOnly,
                    url: String = "https://example.com/",
                    method: HttpMethod = HttpMethod.Post,
                    attestation: JwsCompactTyped<JsonWebToken> = clientAttestation,
                    dpopSigner: SignJwtFun<JsonWebToken> = SignJwt(clientKey, JwsHeaderJwk()),
                ): RequestInfo {
                    val dpop = BuildDPoPHeader(
                        signDpop = dpopSigner,
                        url = url,
                        httpMethod = method.value,
                        nonce = server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge,
                        randomSource = RandomSource.Default,
                    )
                    return RequestInfo(
                        url = url,
                        method = method,
                        headers = headers {
                            append(HttpHeaders.OAuthClientAttestation, attestation.toString())
                            append(HttpHeaders.DPoP, dpop.toString())
                        },
                    )
                }

                /** A request in normal mode: attestation plus a dedicated PoP JWT, and no DPoP proof. */
                suspend fun normalModeRequest(
                    server: SimpleAuthorizationService,
                    url: String = "https://example.com/",
                ): RequestInfo {
                    val pop = BuildClientAttestationPoPJwt(
                        signJwt = SignJwt(clientKey, JwsHeaderNone()),
                        audience = AUTHORIZATION_SERVER,
                        nonce = server.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge,
                        randomSource = RandomSource.Default,
                    )
                    return RequestInfo(
                        url = url,
                        method = HttpMethod.Post,
                        headers = headers {
                            append(HttpHeaders.OAuthClientAttestation, clientAttestation.toString())
                            append(HttpHeaders.OAuthClientAttestationPop, pop.toString())
                        },
                    )
                }

                suspend fun par(server: SimpleAuthorizationService, httpRequest: RequestInfo) = server.par(
                    client.createAuthRequestJar(state = uuid4().toString(), scope = scope),
                    httpRequest,
                ).getOrThrow()
            }
        }
    } - {

        test("combined mode accepts attestation with a DPoP proof for the attested key at PAR") {
            it.par(it.combinedOnly, it.combinedRequest())
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
                .requestUri.shouldNotBeNull()
        }

        test("combined mode accepts the same client at the token endpoint") {
            val state = uuid4().toString()
            val parResponse = it.combinedOnly.par(
                it.client.createAuthRequestJar(state = state, scope = it.scope),
                it.combinedRequest(),
            ).getOrThrow().shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val code = it.combinedOnly
                .authorize(it.client.createAuthRequestAfterPar(parResponse) as RequestParameters) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params?.code.shouldNotBeNull()

            it.combinedOnly.token(
                request = it.client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = it.scope,
                ),
                httpRequest = it.combinedRequest(),
            ).getOrThrow().accessToken.shouldNotBeNull()
        }

        test("combined mode rejects a DPoP proof from a key the attestation does not confirm") {
            // The whole point of 5.2: the DPoP key must be the key in cnf.jwk, otherwise the proof says nothing
            // about possession of the attested key
            shouldThrow<OAuth2Exception> {
                it.par(
                    it.combinedOnly,
                    it.combinedRequest(dpopSigner = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderJwk())),
                )
            }
        }

        test("combined mode rejects a request without any proof of possession") {
            val attestationOnly = RequestInfo(
                url = "https://example.com/",
                method = HttpMethod.Post,
                headers = headers {
                    append(HttpHeaders.OAuthClientAttestation, it.clientAttestation.toString())
                },
            )

            shouldThrow<OAuth2Exception> {
                it.par(it.combinedOnly, attestationOnly)
            }
        }

        test("combined mode rejects a dedicated attestation PoP JWT") {
            // draft-10 7: the accepted PoP method is configuration, not the client's choice
            shouldThrow<OAuth2Exception> {
                it.par(it.combinedOnly, it.normalModeRequest(it.combinedOnly))
            }
        }

        test("accepting both methods accepts a normal mode request") {
            // An AS advertising both methods lets the client pick, so a dedicated PoP without any DPoP proof must
            // still authenticate: requiring both proofs at once is neither mode
            it.par(it.bothModes, it.normalModeRequest(it.bothModes))
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
        }

        test("accepting both methods accepts a combined mode request") {
            it.par(it.bothModes, it.combinedRequest(server = it.bothModes))
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
        }

        test("combined mode rejects a dedicated PoP even alongside a valid DPoP proof") {
            // draft-10 7: the configured method is not negotiable, so normal mode must not be reachable on an AS
            // that only advertises attest_jwt_client_auth_dpop
            shouldThrow<OAuth2Exception> {
                it.par(it.combinedOnly, it.bothProofsRequest(it.combinedOnly))
            }
        }

        test("normal mode rejects a combined mode request") {
            shouldThrow<OAuth2Exception> {
                it.par(it.normalOnly, it.combinedRequest(server = it.normalOnly))
            }
        }

        test("reject duplicate client attestation headers") {
            // draft-10 7: exactly one attestation, so a second header cannot be smuggled past the parsed
            // single-value accessor
            val second = BuildClientAttestationJwt(
                it.attesterBackend,
                clientId = it.client.clientId,
                clientKey = EphemeralKeyWithoutCert().jsonWebKey,
            )
            val dpop = BuildDPoPHeader(
                signDpop = SignJwt(it.clientKey, JwsHeaderJwk()),
                url = "https://example.com/",
                nonce = it.combinedOnly.attestationChallenge().getOrThrow()
                    .shouldNotBeNull().attestationChallenge,
                randomSource = RandomSource.Default,
            )
            val duplicated = RequestInfo(
                url = "https://example.com/",
                method = HttpMethod.Post,
                headers = headers {
                    append(HttpHeaders.OAuthClientAttestation, it.clientAttestation.toString())
                    append(HttpHeaders.OAuthClientAttestation, second.toString())
                    append(HttpHeaders.DPoP, dpop.toString())
                },
            )

            shouldThrow<OAuth2Exception> {
                it.par(it.combinedOnly, duplicated)
            }
        }

        test("metadata advertises only the configured PoP method") {
            it.combinedOnly.metadata().apply {
                tokenEndPointAuthMethodsSupported.shouldNotBeNull()
                    .shouldContain(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP)
                tokenEndPointAuthMethodsSupported.shouldNotBeNull()
                    .shouldNotContain(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH)
                clientAttestationPopMethodsSupported shouldBe setOf(ClientAttestationPopMethod.DpopCombined)
                // combined mode is unusable without DPoP, so the AS must publish its DPoP algorithms
                dpopSigningAlgValuesSupportedStrings.shouldNotBeNull().isNotEmpty() shouldBe true
            }

            it.normalOnly.metadata().apply {
                tokenEndPointAuthMethodsSupported.shouldNotBeNull()
                    .shouldContain(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH)
                tokenEndPointAuthMethodsSupported.shouldNotBeNull()
                    .shouldNotContain(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP)
                clientAttestationPopMethodsSupported shouldBe setOf(ClientAttestationPopMethod.AttestationPopJwt)
            }
        }
    }
}
