package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.openid.CredentialOffer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.WalletService
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.URLBuilder
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.SerializationException

val CredentialOfferParsingTest by matrixSuite {
    val offer = CredentialOffer(
        credentialIssuer = "https://issuer.example.org",
        configurationIds = setOf("example-credential"),
    )
    val json = joseCompliantSerializer.encodeToString(offer)
    val input = "haip-vci://?credential_offer_uri=https://issuer.example.org/offer"

    "raw JSON and embedded offers do not fetch resources" {
        val service = WalletService(remoteResourceRetriever = { error("Unexpected retrieval") })
        service.parseCredentialOffer("  $json").getOrThrow() shouldBe offer
        val embedded = URLBuilder("haip-vci://").apply {
            parameters.append("credential_offer", json)
        }.buildString()
        service.parseCredentialOffer(embedded).getOrThrow() shouldBe offer
    }

    "referenced JSON is decoded" {
        val service = WalletService(remoteResourceRetriever = { json })
        service.parseCredentialOffer(input).getOrThrow() shouldBe offer
    }

    "retrieval failures are preserved unchanged including nested offer URLs" {
        val failure = IllegalStateException("Simulated connection timeout")
        val nested = "haip-vci://?credential_offer_uri=https://issuer.example.org/second"
        for (response in listOf<String?>(null, nested)) {
            var calls = 0
            val service = WalletService(remoteResourceRetriever = {
                calls++
                if (response != null && calls == 1) response else throw failure
            })
            service.parseCredentialOffer(input).exceptionOrNull() shouldBe failure
            calls shouldBe if (response == null) 1 else 2
        }
    }

    "malformed downloaded JSON preserves its decoding cause" {
        val service = WalletService(remoteResourceRetriever = { "{\"credential_issuer\":" })
        val failure = service.parseCredentialOffer(input).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        failure.cause.shouldBeInstanceOf<SerializationException>()
    }

    "missing response and unrecognized input have explicit errors" {
        val service = WalletService(remoteResourceRetriever = { null })
        service.parseCredentialOffer(input).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
            .message shouldBe "invalid_request: credential offer retrieval returned no response"
        service.parseCredentialOffer("haip-vci://?unrelated=value").exceptionOrNull()
            .shouldBeInstanceOf<InvalidRequest>()
    }

    "cancellation propagates instead of becoming a failed result" {
        val cancellation = CancellationException("Session closed")
        val service = WalletService(remoteResourceRetriever = { throw cancellation })
        shouldThrow<CancellationException> {
            service.parseCredentialOffer(input)
        } shouldBe cancellation
    }
}
