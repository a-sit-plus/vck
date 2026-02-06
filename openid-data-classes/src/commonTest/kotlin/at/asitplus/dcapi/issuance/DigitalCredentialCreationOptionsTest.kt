package at.asitplus.dcapi.issuance

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val DigitalCredentialCreationOptionsTest by testSuite {
    test("https://digital-credentials.dev/dmv JSON parses") {
        val options = joseCompliantSerializer.decodeFromString<DigitalCredentialCreationOptions>(DIGITAL_CREDENTIALS_DEV_JSON)
        options.requests.size shouldBe 1

        val creationOptions = CredentialCreationOptions.create(options)
        creationOptions.mediation shouldBe "required"
        creationOptions.digital shouldBe options
    }

    test("authorization_server_metadata and authorization_server are mutually exclusive") {
        val ex = shouldThrow<IllegalArgumentException> {
            joseCompliantSerializer.decodeFromString<DigitalCredentialCreationOptions>(WRONG_ISSUER_JSON)
        }
    }
}
