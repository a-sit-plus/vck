package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.buildDPoPHeader
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

class OAuth2ClientDPoPTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var authorizationServiceStrategy: AuthorizationServiceStrategy
    lateinit var server: SimpleAuthorizationService
    lateinit var clientKey: KeyMaterial
    lateinit var jwsService: JwsService

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()), JsonObject(mapOf()))
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
            enforceDpop = true,
        )
        clientKey = EphemeralKeyWithSelfSignedCert()
        jwsService = DefaultJwsService(DefaultCryptoService(clientKey))
    }

    suspend fun getCode(state: String): String {
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val authnResponse = server.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        return code
    }

    test("authorization code flow with DPoP") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            dpop = jwsService.buildDPoPHeader("url")
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        val dpopForResource = jwsService.buildDPoPHeader("url", accessToken = token.accessToken)
        // this is our protected resource
        server.getUserInfo(
            token.toHttpHeaderValue(),
            dpopHeader = dpopForResource,
            credentialIdentifier = null,
            credentialConfigurationId = scope
        ).getOrThrow()
    }

    test("authorization code flow without DPoP for resource") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            dpop = jwsService.buildDPoPHeader("url")
        ).getOrThrow().also {
            it.tokenType shouldBe TOKEN_TYPE_DPOP
        }

        // this is our protected resource
        shouldThrow<OAuth2Exception> {
            server.getUserInfo(
                token.toHttpHeaderValue(),
                dpopHeader = null,
                credentialIdentifier = null,
                credentialConfigurationId = scope
            ).getOrThrow()
        }
    }

    test("authorization code flow with DPoP from other key") {
        val state = uuid4().toString()
        val code = getCode(state)

        val token = server.token(
            client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = scope
            ),
            dpop = jwsService.buildDPoPHeader("url")
        ).getOrThrow()

        val wrongJwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert()))
        // TODO Test and assert URL
        val dpopForResource = wrongJwsService.buildDPoPHeader("url", accessToken = token.accessToken)

        // this is our protected resource
        shouldThrow<OAuth2Exception> {
            server.getUserInfo(
                token.toHttpHeaderValue(),
                dpopHeader = dpopForResource,
                credentialIdentifier = null,
                credentialConfigurationId = scope
            ).getOrThrow()
        }
    }
})