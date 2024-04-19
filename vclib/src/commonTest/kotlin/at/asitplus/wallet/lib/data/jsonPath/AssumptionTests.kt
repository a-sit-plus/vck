package at.asitplus.wallet.lib.data.jsonPath

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

class AssumptionTests : FreeSpec({
    "assumption:e7c1e659-1d42-4632-8d92-1ab4f73ae4da: JsonPrimitive.*OrNull also returns value for valid string representations" - {
        "assumption:9e5217e5-d0ee-42e3-a274-b4babf6a3a2e: JsonPrimitive.booleanOrNull returns value if it was constructed from boolean or is a stringified boolean" - {
            "returns false when being constructed from false" {
                val jsonElement = JsonPrimitive(false)
                jsonElement.booleanOrNull shouldBe false
            }
            "returns true when being constructed from true" {
                val jsonElement = JsonPrimitive(true)
                jsonElement.booleanOrNull shouldBe true
            }
            "returns null when being constructed from null" {
                val jsonElement = JsonNull
                jsonElement.booleanOrNull shouldBe null
            }
            "returns null when being constructed from string" - {
                "when string is not a representation of a boolean" {
                    val jsonElement = JsonPrimitive("test")
                    jsonElement.booleanOrNull shouldBe null
                }
                "when string is actually a representation of a boolean" {
                    val jsonElement = JsonPrimitive(true.toString())
                    jsonElement.booleanOrNull shouldBe true
                }
            }
            "returns null when being constructed from number" {
                val jsonElement = JsonPrimitive(42)
                jsonElement.booleanOrNull shouldBe null
            }
        }
        "assumption:9e5217e5-d0ee-42e3-a274-b4babf6a3a2e: JsonPrimitive.longOrNull returns value if it was constructed from long or is a stringified long" - {
            "returns null when being constructed from false" {
                val jsonElement = JsonPrimitive(false)
                jsonElement.longOrNull shouldBe null
            }
            "returns null when being constructed from true" {
                val jsonElement = JsonPrimitive(true)
                jsonElement.longOrNull shouldBe null
            }
            "returns null when being constructed from null" {
                val jsonElement = JsonNull
                jsonElement.longOrNull shouldBe null
            }
            "returns null when being constructed from string" - {
                "when string is not a representation of a long" {
                    val jsonElement = JsonPrimitive("test")
                    jsonElement.longOrNull shouldBe null
                }
                "when string is a representation of double with fractional part" {
                    val jsonElement = JsonPrimitive(12.34.toString())
                    jsonElement.longOrNull shouldBe null
                }
                "when string is a representation of double with fractional part using exponents" {
                    val jsonElement = JsonPrimitive("1234e-2")
                    jsonElement.longOrNull shouldBe null
                }
            }
            "returns value when being constructed from string" - {
                "when string is actually a representation of a long" {
                    val jsonElement = JsonPrimitive(42.toString())
                    jsonElement.longOrNull shouldBe 42
                }
                "when string is actually a representation of a long, but with exponents" {
                    val jsonElement = JsonPrimitive("42e+5")
                    jsonElement.longOrNull shouldBe 4200000
                }
            }
            "returns long when being constructed from long" {
                val jsonElement = JsonPrimitive(42)
                jsonElement.longOrNull shouldBe 42
            }
        }
    }
    "assumption:416dc455-ebb7-4b74-86e4-b63dc8cfe279: JsonArray.toString() yields a serialized json array without double quotes" {
        val jsonArray = buildJsonArray {
            for (value in listOf("a", "b", "c")) {
                add(value)
            }
        }
        jsonArray.toString() shouldBe "[\"a\",\"b\",\"c\"]"
    }
    "assumption:ee3a76b1-0906-4a42-8b8c-0e81e41ecc58: JsonPrimitive.doubleOrNull returns a value for integers as well" {
        val jsonElement = JsonPrimitive(42)
        jsonElement.doubleOrNull.shouldNotBeNull()
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