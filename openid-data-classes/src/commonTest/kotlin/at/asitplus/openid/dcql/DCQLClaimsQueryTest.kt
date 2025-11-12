package at.asitplus.openid.dcql

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val DCQLClaimsQueryTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLClaimsQuery.SerialNames.ID shouldBe "id"
            DCQLClaimsQuery.SerialNames.VALUES shouldBe "values"
        }
    }
    "serialization" - {
        "iso" {
            val value = DCQLIsoMdocClaimsQuery(
                id = DCQLClaimsQueryIdentifier("test"),
                namespace = "dummyNamespace",
                claimName = "dummyClaimName"
            )

            val base: DCQLClaimsQuery = value
            val serialized = Json.encodeToJsonElement(base)
            serialized shouldBe Json.encodeToJsonElement(value)
            serialized.jsonObject.entries shouldHaveSize 3

            DCQLClaimsQuery.SerialNames.ID shouldBeIn serialized.jsonObject.keys
            DCQLIsoMdocClaimsQuery.SerialNames.NAMESPACE shouldBeIn serialized.jsonObject.keys
            DCQLIsoMdocClaimsQuery.SerialNames.CLAIM_NAME shouldBeIn serialized.jsonObject.keys
        }
        "other" {
            val value = DCQLJsonClaimsQuery(
                id = DCQLClaimsQueryIdentifier("test"),
                path = DCQLClaimsPathPointer("test") + null + null,
            )

            value.path.segments shouldHaveSize 3

            val base: DCQLClaimsQuery = value
            val serialized = Json.encodeToJsonElement(base)
            serialized shouldBe Json.encodeToJsonElement(value)
            serialized.jsonObject.entries shouldHaveSize 2

            DCQLClaimsQuery.SerialNames.ID shouldBeIn serialized.jsonObject.keys
            DCQLJsonClaimsQuery.SerialNames.PATH shouldBeIn serialized.jsonObject.keys
        }
    }
}