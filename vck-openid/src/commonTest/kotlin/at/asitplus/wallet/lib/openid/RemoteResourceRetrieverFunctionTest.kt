package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.WalletService
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking

private data class FakeHttpResponse(
    val body: String? = null,
    val location: String? = null,
)

private class FakeRemoteResourceRetriever(
    private val responses: Map<String, FakeHttpResponse>,
) {
    suspend fun invoke(input: RemoteResourceRetrieverInput): String? {
        val response = responses[input.url] ?: return null
        return response.body ?: response.location
    }
}

val RemoteResourceRetrieverFunctionTest by matrixSuite {
    val requestUri = "https://client.example.org/request"
    val authnRequest = AuthenticationRequestParameters(
        responseType = "vp_token",
        clientId = "client.example.org",
        redirectUrl = "https://client.example.org/callback",
        scope = "openid",
    )

    // OpenID4VP 1.0, 5.10.1 requires the request URI response to be a signed request object, so serve one of those
    val authnRequestSigned = runBlocking {
        SignJwt<RequestParameters>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST, authnRequest, RequestParameters.serializer()
        ).getOrThrow().toString()
    }

    "body response is used when present" {
        val retriever = FakeRemoteResourceRetriever(
            mapOf(
                requestUri to FakeHttpResponse(
                    body = authnRequestSigned,
                    location = "https://redirect.example.org/not-used",
                )
            )
        )
        val parser = RequestParser(remoteResourceRetriever = retriever::invoke)
        val input = URLBuilder("https://example.com").apply {
            parameters.append("request_uri", requestUri)
            parameters.append("client_id", "somevalue")
        }.buildString()

        parser.parseRequestParameters(input).getOrThrow().apply {
            shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
            shouldBeInstanceOf<RequestParametersFrom.Jws<*>>()
            jws.toString() shouldBe authnRequestSigned
            parameters shouldBe authnRequest
        }
    }

    "location response is used when body missing" {
        val offerUri = "https://issuer.example.org/credential-offer"
        val offer = CredentialOffer(
            credentialIssuer = "https://issuer.example.org",
            configurationIds = setOf("example-credential"),
        )
        val offerJson = joseCompliantSerializer.encodeToString(offer)
        val locationUrl = URLBuilder("https://redirect.example.org/offer").apply {
            parameters.append("credential_offer", offerJson)
        }.buildString()
        val retriever = FakeRemoteResourceRetriever(
            mapOf(
                offerUri to FakeHttpResponse(
                    location = locationUrl,
                )
            )
        )
        val walletService = WalletService(remoteResourceRetriever = retriever::invoke)
        val input = URLBuilder("https://wallet.example.org").apply {
            parameters.append("credential_offer_uri", offerUri)
        }.buildString()

        walletService.parseCredentialOffer(input).getOrThrow() shouldBe offer
    }
}
