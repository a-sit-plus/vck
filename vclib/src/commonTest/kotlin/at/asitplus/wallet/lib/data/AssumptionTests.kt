package at.asitplus.wallet.lib.data

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray

class AssumptionTests : FreeSpec({
    "assumption:416dc455-ebb7-4b74-86e4-b63dc8cfe279: JsonArray.toString() yields a serialized json array without double quotes" {
        val jsonArray = buildJsonArray {
            for (value in listOf("a", "b", "c")) {
                add(value)
            }
        }
        jsonArray.toString() shouldBe "[\"a\",\"b\",\"c\"]"
    }
    "assumption:325a6913-4576-4f80-9589-17a841126fbf: Regex(str).match(str) returns true" {
        val dummyString = "adsahdbfsjbdf"
        Regex("dummyString").matches("dummyString") shouldBe true
    }
    "assumption:50c2c2bc-df25-4e9d-9890-67bde5a0e677: jsonSerializer.decodeFromString<JsonElement> works as expected" - {
        "assumption:dfc5faa5-6022-47ec-8b2d-520f2fadae86: jsonSerializer.decodeFromString decodes strings to JsonPrimitive" {
            val dummyString = "adsahdbfsjbdf"
            val parsedJsonElement = Json.decodeFromString<JsonElement>(dummyString)
            parsedJsonElement.shouldBeInstanceOf<JsonPrimitive>()
        }
        "assumption:5eabcd14-d840-437f-baf4-b1cd18115213: jsonSerializer.decodeFromString decodes array to JsonArray" {
            val dummyString = "[\"a\",\"b\",\"c\"]"
            val parsedJsonElement = Json.decodeFromString<JsonElement>(dummyString)
            parsedJsonElement.shouldBeInstanceOf<JsonArray>()
        }
        "assumption:74756f2f-1ddd-4929-9b7b-ae4cb1ff7598: jsonSerializer.decodeFromString decodes object to JsonObject" {
            val dummyString = "{\"a\":\"b\"}"
            val parsedJsonElement = Json.decodeFromString<JsonElement>(dummyString)
            parsedJsonElement.shouldBeInstanceOf<JsonObject>()
        }
    }
})