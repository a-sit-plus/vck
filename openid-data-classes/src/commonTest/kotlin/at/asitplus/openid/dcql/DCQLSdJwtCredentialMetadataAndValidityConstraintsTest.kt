package at.asitplus.openid.dcql

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

class DCQLSdJwtCredentialMetadataAndValidityConstraintsTest : FreeSpec({
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
})