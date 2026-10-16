package at.asitplus.openid

import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Pins the authorization error response parameters (`error`, `error_description`, `error_uri`) of
 * [AuthenticationResponseParameters] on every transport of OpenID4VP 1.0: form posts (8.2), JWT payloads of encrypted
 * responses (8.3.1), and the `data` object of the Digital Credentials API (A.4).
 */
val AuthenticationResponseParametersTest by matrixSuite {

    test("the authorization error response of OpenID4VP 1.0, 8.2 decodes from a form post") {
        val body = "error=invalid_request&error_description=unsupported%20client_id_prefix&state=eyJhb...6-sVA"

        body.decodeFromFormUrlEncoded<AuthenticationResponseParameters>() shouldBe AuthenticationResponseParameters(
            error = "invalid_request",
            errorDescription = "unsupported client_id_prefix",
            state = "eyJhb...6-sVA",
        )
    }

    test("an authorization error response survives a round-trip through a form post") {
        val input = AuthenticationResponseParameters(
            error = "access_denied",
            errorDescription = "user declined",
            errorUri = "https://wallet.example.com/errors/access_denied",
            state = "state",
        )

        input.encodeToParameters() shouldBe mapOf(
            "error" to "access_denied",
            "error_description" to "user declined",
            "error_uri" to "https://wallet.example.com/errors/access_denied",
            "state" to "state",
        )
        input.encodeToFormUrlEncoded().decodeFromFormUrlEncoded<AuthenticationResponseParameters>() shouldBe input
    }

    test("an authorization error response decodes from the JSON payload of an encrypted response") {
        val payload = """{"error":"access_denied","error_description":"user declined",""" +
                """"error_uri":"https://wallet.example.com/errors/access_denied","state":"state"}"""

        val decoded = joseCompliantSerializer.decodeFromString<AuthenticationResponseParameters>(payload)

        decoded shouldBe AuthenticationResponseParameters(
            error = "access_denied",
            errorDescription = "user declined",
            errorUri = "https://wallet.example.com/errors/access_denied",
            state = "state",
        )
        joseCompliantSerializer.decodeFromString<AuthenticationResponseParameters>(
            joseCompliantSerializer.encodeToString(decoded)
        ) shouldBe decoded
    }

    "the error object of OpenID4VP 1.0, A.4 is the data of a Digital Credentials API response" - {
        val error = AuthenticationResponseParameters(error = "invalid_request")
        mapOf(
            "openid4vp-v1-unsigned" to OpenId4VpResponseUnsigned(error),
            "openid4vp-v1-signed" to OpenId4VpResponseSigned(error),
        ).asData() test { (protocol, expected) ->
            val json = """{"protocol":"$protocol","data":{"error":"invalid_request"}}"""

            val decoded = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(json)

            decoded.shouldBeInstanceOf<OpenId4VpResponse>().data shouldBe error
            decoded shouldBe expected
            joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(expected) shouldBe json
        }
    }
}
