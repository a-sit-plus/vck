package at.asitplus.openid.dcql

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

class DCQLCredentialMetadataAndValidityConstraintsTest : FreeSpec({
     "serialization" - {
         "iso" {
             val value = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                 doctypeValue = "test"
             )

             val base: DCQLCredentialMetadataAndValidityConstraints = value
             val serialized = Json.encodeToJsonElement(base)
             serialized shouldBe Json.encodeToJsonElement(value)
             serialized.jsonObject.entries shouldHaveSize 1

             DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBeIn serialized.jsonObject.keys
         }
         "sd-jwt" {
             val value = at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints(
                 vctValues = listOf("test")
             )

             val base: DCQLCredentialMetadataAndValidityConstraints = value
             val serialized = Json.encodeToJsonElement(base)
             serialized shouldBe Json.encodeToJsonElement(value)
             serialized.jsonObject.entries shouldHaveSize 1

             DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBeIn serialized.jsonObject.keys
         }
     }
})