package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject

class OAuth2ClientTest : FunSpec({

    lateinit var scope: String
    lateinit var client: OAuth2Client
    lateinit var user: OidcUserInfoExtended
    lateinit var server: SimpleAuthorizationService

    beforeEach {
        scope = randomString()
        client = OAuth2Client()
        user = OidcUserInfoExtended(OidcUserInfo(randomString()), JsonObject(mapOf()))
        server = SimpleAuthorizationService(
            strategy = object : AuthorizationServiceStrategy {
                override suspend fun loadUserInfo(
                    request: AuthenticationRequestParameters,
                    code: String,
                ): OidcUserInfoExtended? = user

                override fun filterAuthorizationDetails(authorizationDetails: Set<AuthorizationDetails>): Set<AuthorizationDetails> =
                    setOf()

                override fun filterScope(scope: String): String? = scope

            },
        )
    }

    test("process with pre-authorized code") {
        val preAuth = server.providePreAuthorizedCode(user)
            .shouldNotBeNull()
        val state = uuid4().toString()
        val tokenRequest = client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
            scope = scope
        )
        val token = server.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()
    }

    test("process with pre-authorized code, can't use it twice") {
        val preAuth = server.providePreAuthorizedCode(user)
            .shouldNotBeNull()
        val state = uuid4().toString()
        val tokenRequest = client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
            scope = scope
        )
        server.token(tokenRequest).isSuccess shouldBe true
        server.token(tokenRequest).isFailure shouldBe true
    }

    test("process with authorization code flow") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
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
        val token = server.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()
    }

})