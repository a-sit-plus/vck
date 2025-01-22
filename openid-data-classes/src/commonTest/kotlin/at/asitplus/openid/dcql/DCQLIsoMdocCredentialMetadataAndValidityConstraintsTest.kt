package at.asitplus.openid.dcql

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
})