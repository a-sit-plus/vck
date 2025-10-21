package at.asitplus.openid.dcql

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryOpenIDFederationTest by testSuite {
    val serializer = DCQLTrustedAuthorityQueryEntryOpenIDFederation.serializer()
    "given serialized version" - {
        "when deserializing as base or derived type" - {
            "then gives same with expected content" - {
                withData(
                    """{ "type": "openid_federation", "values": ["https://trustanchor.example.com"] }""",
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
            "then gives different results" - {
                withData(
                    """{ "type": "aki", "values": ["https://lotl.example.com"] }""",
                    """{ "type": "etsi_tl", "values": ["ttps://lotl.example.com"] }""",
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