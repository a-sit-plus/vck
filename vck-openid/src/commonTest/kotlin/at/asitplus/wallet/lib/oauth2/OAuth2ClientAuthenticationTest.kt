package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.SignKeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

class OAuth2ClientAuthenticationTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var server: SimpleAuthorizationService
    lateinit var clientAttestation: JwsSigned<JsonWebToken>
    lateinit var clientAttestationPop: JwsSigned<JsonWebToken>
    lateinit var clientKey: SignKeyMaterial

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        server = SimpleAuthorizationService(
            strategy = DummyAuthorizationServiceStrategy(scope),
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            )
        )
        val attesterBackend = SignJwt<JsonWebToken>(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk())
        clientKey = EphemeralKeyWithSelfSignedCert()
        clientAttestation = BuildClientAttestationJwt(
            attesterBackend,
            clientId = client.clientId,
            issuer = "someissuer",
            clientKey = clientKey.jsonWebKey
        )

        val signClientAttestationPop: SignJwtFun<JsonWebToken> = SignJwt(clientKey, JwsHeaderNone())
        clientAttestationPop = BuildClientAttestationPoPJwt(signClientAttestationPop, client.clientId, "some server")
    }

    suspend fun getToken(state: String, code: String): TokenResponseParameters = server.token(
        client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope
        ),
        RequestInfo(
            url = "https://example.com/",
            method = HttpMethod.Post,
            dpop = null,
            clientAttestation = clientAttestation.serialize(),
            clientAttestationPop = clientAttestationPop.serialize()
        )
    ).getOrThrow()

    test("pushed authorization request") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val parResponse = server.par(
            authnRequest,
            clientAttestation.serialize(),
            clientAttestationPop.serialize()
        ).getOrThrow()
            .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
        val authnResponse = server
            .authorize(client.createAuthRequestAfterPar(parResponse)) { catching { user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()

        getToken(state, code)
            .authorizationDetails.shouldBeNull()
    }

    test("pushed authorization request with wrong client attestation JWT") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )

        clientAttestation = BuildClientAttestationJwt(
            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
            clientId = "wrong client id",
            issuer = "someissuer",
            clientKey = clientKey.jsonWebKey
        )

        shouldThrow<OAuth2Exception> {
            server.par(
                authnRequest,
                clientAttestation.serialize(),
                clientAttestationPop.serialize()
            ).getOrThrow()
        }
    }

    test("pushed authorization request with client attestation JWT not trusted") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        server = SimpleAuthorizationService(
            strategy = DummyAuthorizationServiceStrategy(scope),
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
                verifyClientAttestationJwt = { false }
            ),
        )

        shouldThrow<OAuth2Exception> {
            server.par(
                authnRequest,
                clientAttestation.serialize(),
                clientAttestationPop.serialize()
            ).getOrThrow()
        }
    }

    test("pushed authorization request without client authentication") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        shouldThrow<OAuth2Exception> {
            server.par(authnRequest).getOrThrow()
        }
    }

    test("authorization code flow and client authentication") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val authnResponse = server.authorize(authnRequest) { catching { user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()

        getToken(state, code)
            .authorizationDetails.shouldBeNull()
    }

    test("authorization code flow without client authentication") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val authnResponse = server.authorize(authnRequest) { catching { user } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()

        val tokenRequest = client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope
        )
        shouldThrow<OAuth2Exception> { server.token(tokenRequest).getOrThrow() }
    }

})