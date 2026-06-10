package at.asitplus.openid

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

@Suppress("unused")
val SupportedCredentialFormatTest by matrixSuite {
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