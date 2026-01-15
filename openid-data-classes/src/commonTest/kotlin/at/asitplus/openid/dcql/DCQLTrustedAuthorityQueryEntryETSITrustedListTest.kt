package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryETSITrustedListTest by testSuite {
    val serializer = DCQLTrustedAuthorityQueryEntryETSITrustedList.serializer()
    "given unserialized version when serializing base type works" - {
        withData(
            DCQLTrustedAuthorityQueryEntryETSITrustedList(
                values = nonEmptyListOf("https://lotl.example.com")
            ),
        ) {
            val pseudoSerialized = Json.encodeToJsonElement(serializer, it)
            val pseudoSerializedBase = Json.encodeToJsonElement(DCQLTrustedAuthorityQueryEntry.serializer(), it)
            pseudoSerialized shouldBe pseudoSerializedBase

            val jsonElement = Json.encodeToJsonElement<DCQLTrustedAuthorityQueryEntryETSITrustedList>(it)
            it.values.shouldBeSingleton().first() shouldBe
                    jsonElement.jsonObject["values"].shouldNotBeNull()
                        .jsonArray.shouldBeSingleton().first().jsonPrimitive.content
        }
    }
    "given serialized version when deserializing base type works" - {
        withData(
            """{ "type": "etsi_tl", "values": ["https://lotl.example.com"] }""",
        ) { string ->
            val deserialized = Json.decodeFromString(serializer, string)
            Json.decodeFromString(DCQLTrustedAuthorityQueryEntry.serializer(), string) shouldBe deserialized

            val jsonElement = Json.decodeFromString(JsonElement.serializer(), string)
            deserialized.values.shouldBeSingleton().first() shouldBe
                    jsonElement.jsonObject["values"].shouldNotBeNull()
                        .jsonArray.shouldBeSingleton().first().jsonPrimitive.content
        }
    }
}