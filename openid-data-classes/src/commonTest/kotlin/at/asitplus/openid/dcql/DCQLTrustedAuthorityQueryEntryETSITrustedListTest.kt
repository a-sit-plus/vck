package at.asitplus.openid.dcql

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryETSITrustedListTest by testSuite {
    val serializer = DCQLTrustedAuthorityQueryEntryETSITrustedList.serializer()
    "given serialized version" - {
        "when deserializing as base or derived type" - {
            "then gives same with expected content" - {
                withData(
                    """{ "type": "etsi_tl", "values": ["https://lotl.example.com"] }""",
                ) { string ->
                    val deserialized = Json.decodeFromString(serializer, string)
                    Json.decodeFromString(
                        DCQLTrustedAuthorityQueryEntry.serializer(),
                        string
                    ) shouldBe deserialized

                    val jsonElement = Json.decodeFromString(
                        JsonElement.serializer(),
                        string
                    )
                    deserialized.values.first() shouldBe jsonElement.jsonObject["values"]!!.jsonArray.first().jsonPrimitive.content
                }
            }
        }
    }
    "given serialized version with incorrect type discriminator" - {
        "when deserializing as base or derived type" - {
            "then gives different results if deserialization is success" - {
                withData(
                    """{ "type": "aki", "values": ["https://lotl.example.com"] }""",
                    """{ "type": "openid_federation", "values": ["https://trustanchor.example.com"] }""",
                ) { string ->
                    try {
                        val deserialized = Json.decodeFromString(serializer, string)
                        Json.decodeFromString(
                            DCQLTrustedAuthorityQueryEntry.serializer(),
                            string
                        ) shouldNotBe deserialized
                    } catch (_: Throwable) {
                        // no statement about exception
                    }
                }
            }
        }
    }
}