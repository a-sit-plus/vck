package at.asitplus.openid

import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

@Suppress("unused")
val SupportedCredentialFormatTest by testSuite {
    testSuite("mdoc format deserialization") {
        withDataSuites(
            """{"doctype": "eu.pid.1", "format": "mso_mdoc"}""",
        ) { serialized ->
            withData(
                SupportedCredentialFormat.serializer(),
                SupportedCredentialFormatMsoMdoc.serializer(),
            ) { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatMsoMdoc>()
            }
        }
    }

    testSuite("sd jwt format deserialization") {
        withDataSuites(
            """{"vct": "eu.pid.1", "format": "dc+sd-jwt"}""",
        ) { serialized ->
            withData(
                SupportedCredentialFormat.serializer(),
                SupportedCredentialFormatSdJwt.serializer(),
            ) { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatSdJwt>()
            }
        }
    }

    testSuite("w3c vc jwt format deserialization") {
        withDataSuites(
            """{ "credential_definition": { "type": ["eu.pid.1"] }, "format": "jwt_vc_json"}""".trimMargin(),
        ) { serialized ->
            withData(
                SupportedCredentialFormat.serializer(),
                SupportedCredentialFormatW3cVcJwt.serializer(),
            ) { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJwt>()
            }
        }
    }

    testSuite("w3c vc json ld format deserialization") {
        withDataSuites(
            """{ "credential_definition": { "@context": ["${W3cVerifiableCredentialsContext.FIRST}"], "type": ["eu.pid.1"] }, "format": "ldp_vc"}""",
        ) { serialized ->
            withData(
                SupportedCredentialFormat.serializer(),
                SupportedCredentialFormatW3cVcJsonLd.serializer(),
            ) { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJsonLd>()
            }
        }
    }

    testSuite("w3c vc jwt + json ld format deserialization") {
        withDataSuites(
            """{ "credential_definition": { "@context": ["${W3cVerifiableCredentialsContext.FIRST}"], "type": ["eu.pid.1"] }, "format": "jwt_vc_json-ld"}""",
        ) { serialized ->
            withData(
                SupportedCredentialFormat.serializer(),
                SupportedCredentialFormatW3cVcJwtJsonLd.serializer(),
            ) { serializer ->
                Json.decodeFromString(
                    serializer,
                    serialized
                ).shouldBeInstanceOf<SupportedCredentialFormatW3cVcJwtJsonLd>()
            }
        }
    }
}