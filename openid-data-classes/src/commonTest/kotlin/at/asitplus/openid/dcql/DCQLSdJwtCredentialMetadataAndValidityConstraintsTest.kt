package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val DCQLSdJwtCredentialMetadataAndValidityConstraintsTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBe "vct_values"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type")
            )
        ).jsonObject
        DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBeIn serialized.keys
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validate("dummy document type").getOrThrow()

            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.DC_SD_JWT,
                credentialMetadataAndValidityConstraints = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("dummy document type"),
                ),
                mdocCredentialDoctypeExtractor = {
                    throw IllegalArgumentException("MDOC credential type cannot be extracted")
                },
                sdJwtCredentialTypeExtractor = { "dummy document type" },
                jwtVcCredentialTypeExtractor = {
                    throw IllegalArgumentException("JWT-VC credential type cannot be extracted")
                }
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validate("DIFFERENT dummy document type").getOrThrow()
        }
        shouldThrowAny {
            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.DC_SD_JWT,
                credentialMetadataAndValidityConstraints = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("dummy document type"),
                ),
                mdocCredentialDoctypeExtractor = {
                    throw IllegalArgumentException("MDOC credential type cannot be extracted")
                },
                sdJwtCredentialTypeExtractor = { "DIFFERENT dummy document type" },
                jwtVcCredentialTypeExtractor = {
                    throw IllegalArgumentException("JWT-VC credential type cannot be extracted")
                }
            ).getOrThrow()
        }
    }
}