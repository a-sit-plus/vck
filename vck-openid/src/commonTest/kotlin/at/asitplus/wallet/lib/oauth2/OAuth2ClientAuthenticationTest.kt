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
                audience = "some server",
                randomSource = RandomSource.Default
            )

            object {
                val scope = randomString()
                val client = client
                val walletProviderCa = walletProviderCa
                var server = SimpleAuthorizationService(
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
                        clientAttestationPop = clientAttestationPop
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
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                RequestInfo(
                    url = "https://example.com/",
                    method = HttpMethod.Get,
                    dpop = null,
                    clientAttestation = it.clientAttestation,
                    clientAttestationPop = it.clientAttestationPop
                )
            ).getOrThrow()
                .shouldBeInstanceOf<TokenIntrospectionResponse>()
                .apply { active shouldBe true }
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

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                RequestInfo(
                    url = "https://example.com/",
                    method = HttpMethod.Get,
                    dpop = null,
                    clientAttestation = it.clientAttestation,
                    clientAttestationPop = it.clientAttestationPop
                )
            ).getOrThrow()
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
