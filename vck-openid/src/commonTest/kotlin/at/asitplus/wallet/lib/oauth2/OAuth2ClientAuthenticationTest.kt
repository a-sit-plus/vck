package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.buildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.buildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject

class OAuth2ClientAuthenticationTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var authorizationServiceStrategy: AuthorizationServiceStrategy
    lateinit var server: SimpleAuthorizationService
    lateinit var clientAttestation: JwsSigned<JsonWebToken>
    lateinit var clientAttestationPop: JwsSigned<JsonWebToken>
    lateinit var clientKey: KeyMaterial

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        authorizationServiceStrategy = object : AuthorizationServiceStrategy {
            override suspend fun loadUserInfo(
                request: AuthenticationRequestParameters,
                code: String,
            ): OidcUserInfoExtended? = user

            override fun validScopes(): String = scope

            override fun validAuthorizationDetails(): Collection<OpenIdAuthorizationDetails> = listOf()

            override fun filterAuthorizationDetails(authorizationDetails: Collection<AuthorizationDetails>): Set<OpenIdAuthorizationDetails> =
                setOf()

            override fun filterScope(scope: String): String? = scope

        }
        server = SimpleAuthorizationService(
            strategy = authorizationServiceStrategy,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            )
        )
        val attesterBackend = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithSelfSignedCert()))
        clientKey = EphemeralKeyWithSelfSignedCert()
        clientAttestation = attesterBackend
            .buildClientAttestationJwt(client.clientId, "someissuer", clientKey.jsonWebKey)
        val jwsService = DefaultJwsService(DefaultCryptoService(clientKey))
        clientAttestationPop = jwsService.buildClientAttestationPoPJwt(client.clientId, "some server")
    }

    suspend fun getToken(state: String, code: String): TokenResponseParameters = server.token(
        client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope
        ),
        clientAttestation.serialize(),
        clientAttestationPop.serialize()
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
        val authnResponse = server.authorize(client.createAuthRequestAfterPar(parResponse)).getOrThrow()
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
        clientAttestation = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithSelfSignedCert()))
            .buildClientAttestationJwt("wrong client id", "someissuer", clientKey.jsonWebKey)

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
            strategy = authorizationServiceStrategy,
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
        val authnResponse = server.authorize(authnRequest).getOrThrow()
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
        val authnResponse = server.authorize(authnRequest).getOrThrow()
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