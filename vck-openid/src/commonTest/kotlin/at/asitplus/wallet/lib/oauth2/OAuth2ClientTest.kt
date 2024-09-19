package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject

class OAuth2ClientTest : FunSpec({

    lateinit var server: SimpleAuthorizationService
    lateinit var client: OAuth2Client

    beforeEach {
        client = OAuth2Client()
        server = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(
                DummyOAuth2DataProvider,
                setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
            ),
        )
    }

    test("process with pre-authorized code") {
        val user = OidcUserInfoExtended(OidcUserInfo("sub"), JsonObject(mapOf()))
        val preAuth = server.providePreAuthorizedCode(user)
            .shouldNotBeNull()
        val state = uuid4().toString()
        val tokenRequest = client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
        )
        val token = server.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()
    }

    test("process with pre-authorized code, can't use it twice") {
        val user = OidcUserInfoExtended(OidcUserInfo("sub"), JsonObject(mapOf()))
        val preAuth = server.providePreAuthorizedCode(user)
            .shouldNotBeNull()
        val state = uuid4().toString()
        val tokenRequest = client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth),
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
        )
        val token = server.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()
    }

})