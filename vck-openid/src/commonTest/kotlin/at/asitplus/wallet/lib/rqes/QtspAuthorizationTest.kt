package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.rqes.helper.DummyValueProvider
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.ktor.http.*


val QtspAuthorizationTest by testSuite {

    val qtspAuthenticationService = SimpleQtspAuthorizationService(
        acceptedCredentials = setOf(ConstantIndex.AtomicAttribute2023),
    )
    val dummyDataProvider = DummyValueProvider()
    val walletService = RqesWalletService()

    "QTSP rejects non CSC authorization details" {
        val serviceAuthReq = walletService.createServiceAuthenticationRequest().copy(
            authorizationDetails = setOf(OpenIdAuthorizationDetails())
        )
        shouldThrow<OAuth2Exception.InvalidAuthorizationDetails> {
            qtspAuthenticationService.authorize(serviceAuthReq as RequestParameters) { catching { dummyUser() } }
                .getOrThrow()
        }
    }

    "CSC Authorization Details match between auth and token request" {
        val signingCert = dummyDataProvider.getCredentialInfo().toSigningCredential()
        val credentialAuthReq = walletService.createCredentialAuthenticationRequest(
            signingCredential = signingCert,
            documentDigests = dummyDataProvider.buildDocumentDigests(),
            hashAlgorithm = Digest.SHA256,
            signatureProperties = RqesWalletService.SignatureProperties()
        )
        val authorize =
            qtspAuthenticationService.authorize(credentialAuthReq as RequestParameters) { catching { dummyUser() } }
                .getOrThrow()
        val redirectUrlParam = Url(authorize.url).parameters
        val credentialTokenReq = walletService.createOAuth2TokenRequest(
            state = redirectUrlParam["state"] ?: throw Exception("No state in URL"),
            authorization = OAuth2Client.AuthorizationForToken.Code(
                redirectUrlParam["code"] ?: throw Exception("Missing authorization")
            ),
            authorizationDetails = credentialAuthReq.authorizationDetails
        )
        qtspAuthenticationService.token(credentialTokenReq, null).getOrThrow()
    }

}

private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()