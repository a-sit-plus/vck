package at.asitplus.openid

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

val SupportedCredentialFormatTest by matrixSuite {
    test("X.509 presentation format does not enable credential issuance") {
        shouldThrowAny {
            Json.decodeFromString<SupportedCredentialFormat>(
                """{"format":"https://cloudsignatureconsortium.org/2025/x509"}""",
            )
        }
    }

    testSuite("mdoc format deserialization") {
        data(
            listOf("""{"doctype": "eu.pid.1", "format": "mso_mdoc"}"""),
        ) - { serialized ->
            data(
                listOf(
                    SupportedCredentialFormat.serializer(),
                    SupportedCredentialFormatIsoMdoc.serializer(),
                )
            ) test { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatIsoMdoc>()
            }
        }
    }

    testSuite("sd jwt format deserialization") {
        data(
            listOf(
                """{"vct": "eu.pid.1", "format": "dc+sd-jwt"}""",
            )
        ) - { serialized ->
            data(
                listOf(
                    SupportedCredentialFormat.serializer(),
                    SupportedCredentialFormatSdJwt.serializer(),
                )
            ) test { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatSdJwt>()
            }
        }
    }

    testSuite("w3c vc jwt format deserialization") {
        data(
            listOf(
                """{ "credential_definition": { "type": ["eu.pid.1"] }, "format": "jwt_vc_json"}""".trimMargin(),
            )
        ) - { serialized ->
            data(
                listOf(
                    SupportedCredentialFormat.serializer(),
                    SupportedCredentialFormatW3cVcJwt.serializer(),
                )
            ) test { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJwt>()
            }
        }
    }

    testSuite("w3c vc json ld format deserialization") {
        data(
            listOf("""{ "credential_definition": { "@context": ["${W3cVerifiableCredentialsContext.FIRST}"], "type": ["eu.pid.1"] }, "format": "ldp_vc"}"""),
        ) - { serialized ->
            data(
                listOf(
                    SupportedCredentialFormat.serializer(),
                    SupportedCredentialFormatW3cVcJsonLd.serializer(),
                )
            ) test { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJsonLd>()
            }
        }
    }

    testSuite("w3c vc jwt + json ld format deserialization") {
        data(
            listOf(
                """{ "credential_definition": { "@context": ["${W3cVerifiableCredentialsContext.FIRST}"], "type": ["eu.pid.1"] }, "format": "jwt_vc_json-ld"}""",
            )
        ) - { serialized ->
            data(
                listOf(
                    SupportedCredentialFormat.serializer(),
                    SupportedCredentialFormatW3cVcJwtJsonLd.serializer(),
                )
            ) test { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJwtJsonLd>()
            }
        }
    }
}
