package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.random.Random

class DCQLJsonClaimsQueryTest : FreeSpec({
    "specification" - {
        "serial names" {
            DCQLJsonClaimsQuery.SerialNames.PATH shouldBe "path"
        }
    }
    "instance serialization" - {
        val value = DCQLJsonClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            path = DCQLClaimsPathPointer("test"),
        )


        val base: DCQLClaimsQuery = value
        val serialized = Json.encodeToJsonElement(base)
        serialized shouldBe Json.encodeToJsonElement(value)
        serialized.jsonObject.entries shouldHaveSize 2

        DCQLClaimsQuery.SerialNames.ID shouldBeIn serialized.jsonObject.keys
        DCQLJsonClaimsQuery.SerialNames.PATH shouldBeIn serialized.jsonObject.keys
    }
    "execution" {
        val credential = buildJsonArray {
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive("test"))
                    add(JsonPrimitive("other"))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive("test"))
                    add(JsonPrimitive("other"))
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive(0))
                    add(JsonPrimitive(1))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive(0))
                    add(JsonPrimitive(1))
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive(true))
                    add(JsonPrimitive(false))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive(true))
                    add(JsonPrimitive(false))
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive(false))
                    add(JsonPrimitive(true))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive(false))
                    add(JsonPrimitive(true))
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive(1))
                    add(JsonPrimitive(0))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive(1))
                    add(JsonPrimitive(0))
                })
            })
            add(buildJsonObject {
                put("a", buildJsonArray {
                    add(JsonPrimitive("other"))
                    add(JsonPrimitive("test"))
                })
                put("b", buildJsonArray {
                    add(JsonPrimitive("other"))
                    add(JsonPrimitive("test"))
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
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.JsonBasedStructure(it)
            },
            credentialQuery = DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.VC_SD_JWT,
            )
        ).getOrThrow().shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>().let {
            it.nodeList shouldHaveSize 3
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
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.JsonBasedStructure(it)
            },
            credentialQuery = DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.MSO_MDOC,
            )
        ).isSuccess shouldBe false
    }
})

