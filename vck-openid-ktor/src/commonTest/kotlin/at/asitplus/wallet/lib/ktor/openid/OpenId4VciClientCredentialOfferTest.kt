package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.CredentialOffer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.engine.mock.*
import io.ktor.http.*

val OpenId4VciClientCredentialOfferTest by matrixSuite {

    val offer = CredentialOffer(
        credentialIssuer = "https://issuer.example.org",
        configurationIds = setOf("example-credential"),
    )

    test("credential offer passed by reference is loaded from the credential issuer") {
        val requestedUrls = mutableListOf<String>()
        val client = OpenId4VciClient(
            engine = MockEngine { request ->
                requestedUrls += request.url.toString()
                when (request.url.toString()) {
                    "https://issuer.example.org/offer" -> respond(
                        joseCompliantSerializer.encodeToString(offer),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                    )

                    else -> respondError(HttpStatusCode.NotFound)
                }
            },
        )

        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/offer")
            .getOrThrow() shouldBe offer
        client.loadCredentialOffer("haip-vci://?credential_offer_uri=https://issuer.example.org/unknown")
            .exceptionOrNull().shouldBeInstanceOf<HttpErrorResponseException>()
            .status shouldBe HttpStatusCode.NotFound
        requestedUrls shouldBe listOf("https://issuer.example.org/offer", "https://issuer.example.org/unknown")
    }
}
