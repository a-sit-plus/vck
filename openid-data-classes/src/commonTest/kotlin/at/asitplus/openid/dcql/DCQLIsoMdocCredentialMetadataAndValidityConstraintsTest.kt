package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

class DCQLIsoMdocCredentialMetadataAndValidityConstraintsTest : FreeSpec({
    "specification" - {
        "serial names" {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBe "doctype_value"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            )
        ).jsonObject
        DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBeIn serialized.keys
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validate("dummy document type").getOrThrow()

            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.MSO_MDOC,
                credentialMetadataAndValidityConstraints = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                    doctypeValue = "dummy document type"
                ),
                mdocCredentialDoctypeExtractor = { "dummy document type" },
                sdJwtCredentialTypeExtractor = {
                    throw IllegalArgumentException("SD-JWT credential type cannot be extracted")
                }
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validate("DIFFERENT dummy document type").getOrThrow()
        }
        shouldThrowAny {
            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.MSO_MDOC,
                credentialMetadataAndValidityConstraints = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                    doctypeValue = "dummy document type"
                ),
                mdocCredentialDoctypeExtractor = { "DIFFERENT dummy document type" },
                sdJwtCredentialTypeExtractor = {
                    throw IllegalArgumentException("SD-JWT credential type cannot be extracted")
                }
            ).getOrThrow()
        }
    }
})