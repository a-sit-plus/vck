package at.asitplus.openid.dcql

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Suppress("unused")
val DCQLJsonClaimsQueryTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLClaimsQuery.SerialNames.PATH shouldBe "path"
        }
    }
    "instance serialization" {
        val value = DCQLJsonClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            path = DCQLClaimsPathPointer("test"),
        )


        val base: DCQLClaimsQuery = value
        val serialized = Json.encodeToJsonElement(base)
        serialized shouldBe Json.encodeToJsonElement(value)
        serialized.jsonObject.entries shouldHaveSize 2

        DCQLClaimsQuery.SerialNames.ID shouldBeIn serialized.jsonObject.keys
        DCQLClaimsQuery.SerialNames.PATH shouldBeIn serialized.jsonObject.keys
    }
    "execution" {
        val credential = buildJsonArray {
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add("test")
                    add("other")
                })
                put("b", buildJsonArray {
                    add("test")
                    add("other")
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(0)
                    add(1)
                })
                put("b", buildJsonArray {
                    add(0)
                    add(1)
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(true)
                    add(false)
                })
                put("b", buildJsonArray {
                    add(true)
                    add(false)
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(false)
                    add(true)
                })
                put("b", buildJsonArray {
                    add(false)
                    add(true)
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(1)
                    add(0)
                })
                put("b", buildJsonArray {
                    add(1)
                    add(0)
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add("other")
                    add("test")
                })
                put("b", buildJsonArray {
                    add("other")
                    add("test")
                })
            })
        }
        DCQLJsonClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            path = DCQLClaimsPathPointer(null) + "a" + 0u,
            values = listOf(
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(0),
                DCQLExpectedClaimValue.BooleanValue(true),
            )
        ).executeJsonClaimsQueryAgainstCredential(
            DCQLCredentialClaimStructure.JsonBasedStructure(credential)
        ).getOrThrow().shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>().let {
            it.nodeList shouldHaveSize 3
        }
    }
}

