package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider.user
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking

val OAuth2ClientAuthenticationTest by testSuite {

    withFixtureGenerator {
        object {
            val scope = randomString()
            val client = OAuth2Client()
            val user = OidcUserInfoExtended(OidcUserInfo(randomString()))
            var server = SimpleAuthorizationService(
                strategy = DummyAuthorizationServiceStrategy(scope),
                clientAuthenticationService = ClientAuthenticationService(
                    enforceClientAuthentication = true,
                )
            )
            val attesterBackend = SignJwt<JsonWebToken>(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk())
            val clientKey = EphemeralKeyWithSelfSignedCert()
            var clientAttestation = runBlocking {
                BuildClientAttestationJwt(
                    attesterBackend,
                    clientId = client.clientId,
                    issuer = "someissuer",
                    clientKey = clientKey.jsonWebKey
                )
            }

            val signClientAttestationPop: SignJwtFun<JsonWebToken> = SignJwt(clientKey, JwsHeaderNone())
            val clientAttestationPop = runBlocking {
                BuildClientAttestationPoPJwt(
                    signJwt = signClientAttestationPop,
                    clientId = client.clientId,
                    audience = "some server",
                    randomSource = RandomSource.Default
                )
            }

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
                    clientAttestation = clientAttestation.serialize(),
                    clientAttestationPop = clientAttestationPop.serialize()
                )
            ).getOrThrow()
        }
    } - {

        test("pushed authorization request") {
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
                    clientAttestation = it.clientAttestation.serialize(),
                    clientAttestationPop = it.clientAttestationPop.serialize()
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
                    clientAttestation = it.clientAttestation.serialize(),
                    clientAttestationPop = it.clientAttestationPop.serialize()
                )
            ).getOrThrow().apply {
                active shouldBe true
            }
        }

        test("pushed authorization request with wrong client attestation JWT") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            it.clientAttestation = BuildClientAttestationJwt(
                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                clientId = "wrong client id",
                issuer = "someissuer",
                clientKey = it.clientKey.jsonWebKey
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = it.clientAttestation.serialize(),
                        clientAttestationPop = it.clientAttestationPop.serialize()
                    )
                ).getOrThrow()
            }
        }

        test("pushed authorization request with client attestation JWT not trusted") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )

            it.server = SimpleAuthorizationService(
                strategy = DummyAuthorizationServiceStrategy(it.scope),
                clientAuthenticationService = ClientAuthenticationService(
                    enforceClientAuthentication = true,
                    verifyClientAttestationJwt = { false }
                ),
            )

            shouldThrow<OAuth2Exception> {
                it.server.par(
                    authnRequest,
                    RequestInfo(
                        url = "https://example.com/",
                        method = HttpMethod.Post,
                        clientAttestation = it.clientAttestation.serialize(),
                        clientAttestationPop = it.clientAttestationPop.serialize()
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
                    clientAttestation = it.clientAttestation.serialize(),
                    clientAttestationPop = it.clientAttestationPop.serialize()
                )
            ).getOrThrow().apply {
                active shouldBe true
            }
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