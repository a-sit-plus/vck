package at.asitplus.dcapi

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val DigitalCredentialInterfaceTest by testSuite {
    test("openid4vp signed response round-trips") {
        val response = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(
            DIGITAL_CREDENTIAL_INTERFACE_SIGNED_RESPONSE_JSON
        )

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(response)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(encoded)

        decoded shouldBe response
    }

    test("openid4vp unsigned response round-trips") {
        val response = OpenId4VpResponseUnsigned(
            data = AuthenticationResponseParameters(state = "state")
        )

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(response)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(encoded)

        decoded shouldBe response
    }

    test("iso mdoc response round-trips") {
        val response = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(
            DIGITAL_CREDENTIAL_INTERFACE_ISO_RESPONSE_JSON
        )

        val encoded = joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(response)
        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(encoded)

        decoded shouldBe response
    }
}
