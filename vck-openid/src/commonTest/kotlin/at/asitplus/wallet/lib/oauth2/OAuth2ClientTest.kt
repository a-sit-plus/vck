package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.randomString
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
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
        user = OidcUserInfoExtended(OidcUserInfo(randomString()))
        server = SimpleAuthorizationService(
            strategy = DummyAuthorizationServiceStrategy(scope),
            dataProvider = DummyDataProvider(user),
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

    test("process with pushed authorization request") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
        )
        val parResponse = server.par(authnRequest).getOrThrow()
            .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
        val authnResponse = server.authorize(client.createAuthRequestAfterPar(parResponse)).getOrThrow()
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

    test("process with authorization code flow, and PAR") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
            wrapAsPar = true
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

    test("process with authorization code flow, front channel") {
        val state = uuid4().toString()
        val authnRequest = client.createAuthRequest(
            state = state,
            scope = scope,
            wrapAsPar = false
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

    test("process with authorization code flow, authn request must contain scope from token request") {
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
            scope = scope.reversed() // invalid, not in authn request
        )
        shouldThrow<OAuth2Exception> {
            server.token(tokenRequest).getOrThrow()
        }
    }

    test("process with authorization code flow, no scope in token request") {
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
            scope = null // already specified in authnrequest
        )
        val token = server.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()
        token.scope.shouldBe(scope)
    }

})