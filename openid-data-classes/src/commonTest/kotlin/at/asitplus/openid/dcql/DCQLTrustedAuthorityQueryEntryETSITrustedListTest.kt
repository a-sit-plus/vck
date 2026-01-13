package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryETSITrustedListTest by testSuite {
    val serializer = DCQLTrustedAuthorityQueryEntryETSITrustedList.serializer()
    "given unserialized version" - {
        "when serializing as base or derived type" - {
            "then gives same with expected content" - {
                withData(
                    DCQLTrustedAuthorityQueryEntryETSITrustedList(
                        values = nonEmptyListOf("https://lotl.example.com")
                    ),
                ) {
                    val pseudoSerialized = Json.encodeToJsonElement(serializer, it)
                    val pseudoSerializedBase = Json.encodeToJsonElement(
                        DCQLTrustedAuthorityQueryEntry.serializer(),
                        it
                    )
                    pseudoSerialized shouldBe pseudoSerializedBase

                    val jsonElement = Json.encodeToJsonElement<DCQLTrustedAuthorityQueryEntryETSITrustedList>(it)
                    it.values.first() shouldBe jsonElement.jsonObject["values"]!!.jsonArray.first().jsonPrimitive.content
                }
            }
        }
    }
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

                    val jsonElement = Json.decodeFromString(JsonElement.serializer(), string)
                    deserialized.values.first() shouldBe jsonElement.jsonObject["values"]!!.jsonArray.first().jsonPrimitive.content
                }
            }
        }
    }
    "given serialized version with incorrect type discriminator" - {
        "when deserializing as this type" - {
            "then deserialization fails" - {
                withData(
                    """{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }""",
                    """{ "type": "openid_federation", "values": ["https://trustanchor.example.com"] }""",
                ) { string ->
                    shouldThrow<Throwable> {
                        Json.decodeFromString(serializer, string)
                    }
                }
            }
        }
    }
}