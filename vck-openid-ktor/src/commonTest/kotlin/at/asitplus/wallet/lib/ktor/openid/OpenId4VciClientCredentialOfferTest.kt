package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.CredentialOffer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*

val OpenId4VciClientCredentialOfferTest by matrixSuite {

    val offer = CredentialOffer(
        credentialIssuer = "https://issuer.example.org",
        configurationIds = setOf("example-credential"),
    )

    fun MockRequestHandleScope.respondOffer() = respond(
        joseCompliantSerializer.encodeToString(offer),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
    )

    test("credential offer passed by reference is loaded from the credential issuer") {
        val requestedUrls = mutableListOf<String>()
        val client = OpenId4VciKtorClient(
            httpClient = HttpClient(MockEngine { request ->
                requestedUrls += request.url.toString()
                when (request.url.toString()) {
                    "https://issuer.example.org/offer" -> respondOffer()

                    else -> respondError(HttpStatusCode.NotFound)
                }
            }),
            oauth2Client = OAuth2Client(),
        )

        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/offer")
            .getOrThrow() shouldBe offer
        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/unknown")
            .exceptionOrNull().shouldBeInstanceOf<HttpErrorResponseException>()
            .status shouldBe HttpStatusCode.NotFound
        requestedUrls shouldBe listOf("https://issuer.example.org/offer", "https://issuer.example.org/unknown")
    }

    test("redirects reach the protocol client, even if the app's HTTP client follows them") {
        val requestedUrls = mutableListOf<String>()
        val client = OpenId4VciKtorClient(
            httpClient = HttpClient(MockEngine { request ->
                requestedUrls += request.url.toString()
                when (request.url.toString()) {
                    "https://issuer.example.org/offer" -> respond(
                        "",
                        HttpStatusCode.Found,
                        headersOf(HttpHeaders.Location, "https://issuer.example.org/moved"),
                    )

                    else -> respondOffer()
                }
            }) { followRedirects = true },
            oauth2Client = OAuth2Client(),
        )

        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/offer")
            .isFailure shouldBe true
        requestedUrls shouldBe listOf("https://issuer.example.org/offer")
    }

    test("deprecated constructor sends with its own HTTP client") {
        @Suppress("DEPRECATION")
        val client = OpenId4VciKtorClient(engine = MockEngine { respondOffer() })

        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/offer")
            .getOrThrow() shouldBe offer
    }
}
