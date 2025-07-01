package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.rqes.helper.DummyValueProvider
import at.asitplus.wallet.lib.rqes.helper.SimpleQtspAuthorizationService
import io.kotest.assertions.throwables.shouldThrow
import kotlinx.coroutines.runBlocking
import io.kotest.core.spec.style.FreeSpec
import io.ktor.http.*


class QtspAuthorizationTest : FreeSpec({

    val qtspAuthenticationService = SimpleQtspAuthorizationService(
        dataProvider = object : OAuth2DataProvider {
            override suspend fun loadUserInfo(
                request: AuthenticationRequestParameters,
                code: String,
            ) = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
        },
        acceptedCredentials = setOf(ConstantIndex.AtomicAttribute2023),
    )
    val dummyDataProvider = DummyValueProvider()
    val walletService = RqesOpenId4VpHolder().apply {
        setSigningCredential(runBlocking { dummyDataProvider.getSigningCredential(true) })
    }

    "QTSP rejects non CSC authorization details" {
        val serviceAuthReq = walletService.createServiceAuthenticationRequest().copy(
            authorizationDetails = setOf(OpenIdAuthorizationDetails())
        )
        shouldThrow<OAuth2Exception.InvalidAuthorizationDetails> {
            qtspAuthenticationService.authorize(
                serviceAuthReq
            ).getOrThrow()
        }
    }

    "CSC Authorization Details match between auth and token request" {
        val credentialAuthReq = walletService.createCredentialAuthenticationRequest(
            documentDigests = dummyDataProvider.buildDocumentDigests(),
            hashAlgorithm = Digest.SHA256
        )
        val redirectUrlParam = Url(qtspAuthenticationService.authorize(credentialAuthReq).getOrThrow().url).parameters
        val credentialTokenReq = walletService.createOAuth2TokenRequest(
            state = redirectUrlParam["state"] ?: throw Exception("No state in URL"),
            authorization = OAuth2Client.AuthorizationForToken.Code(
                redirectUrlParam["code"] ?: throw Exception("Missing authorization")
            ),
            authorizationDetails = credentialAuthReq.authorizationDetails
        )
        qtspAuthenticationService.token(credentialTokenReq).getOrThrow()
    }

})