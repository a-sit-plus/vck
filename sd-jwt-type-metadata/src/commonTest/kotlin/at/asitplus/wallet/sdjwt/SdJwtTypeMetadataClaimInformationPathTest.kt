package at.asitplus.wallet.sdjwt

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

@Suppress("unused")
val SdJwtTypeMetadataClaimInformationPathTest by matrixSuite {
    test("manual examples") {
        val jsonElement = Json.decodeFromString<JsonElement>(
            """
            {
              "vct": "https://betelgeuse.example.com/education_credential/v42",
              "name": "Arthur Dent",
              "address": {
                "street_address": "42 Market Street",
                "city": "Milliways",
                "postal_code": "12345"
              },
              "degrees": [
                {
                  "type": "Bachelor of Science",
                  "university": "University of Betelgeuse"
                },
                {
                  "type": "Master of Science",
                  "university": "University of Betelgeuse"
                }
              ],
              "nationalities": ["British", "Betelgeusian"]
            }
        """.trimIndent()
        )

        SdJwtTypeMetadataClaimInformationPath("name").process(jsonElement).map {
            it.first.toString() to it.second
        } shouldBe listOf(
            (NormalizedJsonPath() + "name") to JsonPrimitive("Arthur Dent")
        ).map {
            it.first.toString() to it.second
        }
        SdJwtTypeMetadataClaimInformationPath("address").process(jsonElement).map {
            it.first.toString() to it.second
        } shouldBe listOf(
            (NormalizedJsonPath() + "address") to Json.decodeFromString<JsonElement>(
                """
                {
                "street_address": "42 Market Street",
                "city": "Milliways",
                "postal_code": "12345"
              }
            """.trimIndent()
            )
        ).map {
            it.first.toString() to it.second
        }
        SdJwtTypeMetadataClaimInformationPath("address", "street_address").process(jsonElement).map {
            it.first.toString() to it.second
        } shouldBe listOf(
            (NormalizedJsonPath() + "address" + "street_address") to JsonPrimitive("42 Market Street")
        ).map {
            it.first.toString() to it.second
        }
        (SdJwtTypeMetadataClaimInformationPath("degrees") + null + "type").process(jsonElement).map {
            it.first.toString() to it.second
        } shouldBe listOf(
            (NormalizedJsonPath() + "degrees" + 0u + "type") to JsonPrimitive("Bachelor of Science"),
            (NormalizedJsonPath() + "degrees" + 1u + "type") to JsonPrimitive("Master of Science"),
        ).map {
            it.first.toString() to it.second
        }
    }

    test("negative numeric path segments are rejected at parse time") {
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""["degrees", -1]""")
        }
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""[-1]""")
        }
    }

    test("path indexes exceeding Int.MAX_VALUE are rejected at parse time") {
        val tooBig = Int.MAX_VALUE.toLong() + 1L
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<SdJwtTypeMetadataClaimInformationPath>("""["degrees", $tooBig]""")
        }
    }
}