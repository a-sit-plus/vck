package at.asitplus.dcapi.request.verifier

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val DigitalCredentialGetRequestTest by testSuite {
    test("openid4vp signed request round-trips") {
        val request = testSignedOpenId4VpRequest

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialGetRequest>(request)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialGetRequest>(encoded)

        decoded shouldBe request
    }

    test("openid4vp unsigned request round-trips") {
        val request = testUnsignedOpenId4VpRequest

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialGetRequest>(request)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialGetRequest>(encoded)

        decoded shouldBe request
    }

    test("iso mdoc request round-trips") {
        val request = testIsoMdocRequest

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialGetRequest>(request)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialGetRequest>(encoded)

        decoded shouldBe request
    }
}
