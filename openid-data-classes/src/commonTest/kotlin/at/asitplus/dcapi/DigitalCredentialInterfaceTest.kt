package at.asitplus.dcapi

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray

val DigitalCredentialInterfaceTest by matrixSuite {
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

    test("Android response JSON preserves the protocol wrapper") {
        val response = OpenId4VpResponseUnsigned(
            data = AuthenticationResponseParameters(state = "state")
        )

        val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(
            response.toAndroidDcApiResponseJson()
        )

        decoded shouldBe response
    }

    test("iOS response bytes contain the Annex C encrypted response") {
        val response = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(
            DIGITAL_CREDENTIAL_INTERFACE_ISO_RESPONSE_JSON
        ) as IsoMdocResponse

        val decoded = coseCompliantSerializer.decodeFromByteArray<EncryptedResponse>(
            response.toIosIsoMdocResponseBytes()
        )

        decoded shouldBe response.data.response
    }

    test("iOS response bytes reject OpenID4VP responses") {
        val response = OpenId4VpResponseUnsigned(
            data = AuthenticationResponseParameters(state = "state")
        )

        shouldThrow<IllegalArgumentException> {
            response.toIosIsoMdocResponseBytes()
        }
    }
}
