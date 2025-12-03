package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.testballoon.withFixtureGenerator
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

val OAuth2ClientTest by testSuite {
    withFixtureGenerator {
        object {
            val scope = randomString()
            val client = OAuth2Client()
            val server = SimpleAuthorizationService(
                strategy = DummyAuthorizationServiceStrategy(scope),
            )
        }
    } - {
        test("process with pre-authorized code") {
            val preAuth = it.server.providePreAuthorizedCode(user)
                .shouldNotBeNull()
            val state = uuid4().toString()
            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow()
            token.authorizationDetails.shouldBeNull()
        }
        test("process with pre-authorized code, can't use it twice") {
            val preAuth = it.server.providePreAuthorizedCode(user)
                .shouldNotBeNull()
            val state = uuid4().toString()
            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
                scope = it.scope
            )
            it.server.token(tokenRequest, null).isSuccess shouldBe true
            it.server.token(tokenRequest, null).isFailure shouldBe true
        }
        test("process with pushed authorization request") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequest(
                state = state,
                scope = it.scope,
            )
            val parResponse = it.server.par(authnRequest as RequestParameters).getOrThrow()
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val input = it.client.createAuthRequestAfterPar(parResponse) as RequestParameters
            val authnResponse = it.server.authorize(input) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }
        }
        test("process with pushed authorization request and JAR") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequestJar(
                state = state,
                scope = it.scope,
            )
            val parResponse = it.server.par(authnRequest).getOrThrow()
                .shouldBeInstanceOf<PushedAuthenticationResponseParameters>()
            val input = it.client.createAuthRequestAfterPar(parResponse) as RequestParameters
            val authnResponse = it.server.authorize(input) { catching { user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()

            val tokenRequest = it.client.createTokenRequestParameters(
                state = state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = it.scope
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }
        }
        test("process with authorization code flow, and JAR") {
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
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
            }
            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }
        }

        test("process with authorization code flow, front channel") {
            val state = uuid4().toString()
            val authnRequest = it.client.createAuthRequest(
                state = state,
                scope = it.scope
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
            val token = it.server.token(tokenRequest, null).getOrThrow()
            token.authorizationDetails.shouldBeNull()
        }

        test("process with authorization code flow, authn request must contain scope from token request") {
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
                scope = it.scope.reversed() // invalid, not in authn request
            )
            shouldThrow<OAuth2Exception> {
                it.server.token(tokenRequest, null).getOrThrow()
            }
        }

        test("process with authorization code flow, no scope in token request") {
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
                scope = null // already specified in authnrequest
            )
            val token = it.server.token(tokenRequest, null).getOrThrow().apply {
                authorizationDetails.shouldBeNull()
                scope.shouldBe(scope)
            }

            it.server.tokenIntrospection(
                TokenIntrospectionRequest(token = token.accessToken),
                null
            ).getOrThrow().apply {
                active shouldBe true
            }
        }
    }
}