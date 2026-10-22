package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.random.nextUInt

val DCQLClaimsPathPointerTest by matrixSuite {
    "processing (OpenID4VP 1.0, 7.1.1)" - {
        val credential = Json.parseToJsonElement(
            """
            {
              "place_of_birth": { "locality": "Wien", "country": "AT" },
              "nationalities": ["AT", "DE"],
              "addresses": [ { "country": "AT" }, { } ],
              "mixed": [ { "x": "yes" }, "text" ],
              "nothing": null
            }
            """.trimIndent()
        )

        "an object is selected as a whole" {
            DCQLClaimsPathPointer("place_of_birth").query(credential).single().value shouldBe
                    credential.jsonObject["place_of_birth"]
        }
        "a wildcard selects every element of an array" {
            (DCQLClaimsPathPointer("nationalities") + null).query(credential).map { it.value } shouldBe
                    listOf(JsonPrimitive("AT"), JsonPrimitive("DE"))
        }
        "an absent key removes that element from the selection" {
            (DCQLClaimsPathPointer("addresses") + null + "country").query(credential).map { it.value } shouldBe
                    listOf(JsonPrimitive("AT"))
        }
        "an absent index removes that array from the selection" {
            (DCQLClaimsPathPointer("nationalities") + 2u).query(credential).shouldBeEmpty()
        }
        "a selected element of the wrong type is an error, even if other selected elements would continue" - {
            listOf(
                DCQLClaimsPathPointer("mixed") + null + "x",
                DCQLClaimsPathPointer("nationalities") + "x",
                DCQLClaimsPathPointer("place_of_birth") + null,
                DCQLClaimsPathPointer("place_of_birth") + 0u,
                DCQLClaimsPathPointer("nothing") + "x",
                DCQLClaimsPathPointer("nationalities") + 0u + "x",
            ).asData(nameFn = { it.toString() }) test { pointer ->
                pointer.query(credential).shouldBeEmpty()
            }
        }
        "a claim with value null is selected" {
            DCQLClaimsPathPointer("nothing").query(credential).single().value shouldBe JsonNull
        }
        "a wildcard over an empty selection is an error" {
            (DCQLClaimsPathPointer("absent") + null).query(credential).shouldBeEmpty()
        }
    }

    "numeric object keys remain names" {
        Json.decodeFromString<DCQLClaimsPathPointer>("""["age_equal_or_over","18"]""") shouldBe
                DCQLClaimsPathPointer("age_equal_or_over", "18")
    }

    "invalid segments are rejected" - {
        listOf("[-1]", "[4294967296]", "[1.5]", "[true]", "[{}]", "[[]]").asData() test { wire ->
            shouldThrowAny { Json.decodeFromString<DCQLClaimsPathPointer>(wire) }
        }
    }

    "constructors" - {
        listOf("test", 0u, null).asData() test {
            when (it) {
                null -> DCQLClaimsPathPointer(it)
                is String -> DCQLClaimsPathPointer(it)
                else -> DCQLClaimsPathPointer(it as UInt)
            }.run {
                segments shouldHaveSize 1
                segments.first().run {
                    when (it) {
                        null -> {
                            shouldBeInstanceOf<NullSegment>()
                        }

                        is String -> {
                            shouldBeInstanceOf<NameSegment>()
                            name shouldBe it
                        }

                        else -> {
                            shouldBeInstanceOf<IndexSegment>()
                            index shouldBe it
                        }
                    }
                }
            }
        }
        listOf(0u, 100u, UInt.MAX_VALUE).asData() test {
            DCQLClaimsPathPointer(it).run {
                segments shouldHaveSize 1
                segments.first().run {
                    shouldBeInstanceOf<IndexSegment>()
                    index shouldBe it
                }
            }
        }
    }
    "concatenation conformance" - {
        "base" {
            val segments = List(1 + Random.nextInt(10)) {
                when (Random.nextInt(3)) {
                    0 -> NameSegment(Base64.encode(Random.nextBytes(32)))
                    1 -> IndexSegment(Random.nextUInt())
                    else -> NullSegment
                }
            }
            DCQLClaimsPathPointer(segments.toNonEmptyList()) shouldBe segments.map {
                DCQLClaimsPathPointer(nonEmptyListOf(it))
            }.reduce { acc, it -> acc + it }
        }
        "values" {
            val segments = List(1 + Random.nextInt(10)) {
                when (Random.nextInt(3)) {
                    0 -> Base64.encode(Random.nextBytes(32))
                    1 -> Random.nextUInt()
                    else -> null
                }
            }

            DCQLClaimsPathPointer(segments.map {
                when (it) {
                    is String -> NameSegment(it)
                    is UInt -> IndexSegment(it)
                    else -> NullSegment
                }
            }.toNonEmptyList()) shouldBe segments.map {
                when (it) {
                    null -> DCQLClaimsPathPointer(it)
                    is String -> DCQLClaimsPathPointer(it)
                    else -> DCQLClaimsPathPointer(it as UInt)
                }
            }.reduce { acc, it -> acc + it }
        }
    }
    "serialization conformance" {
        val segments = List(1 + Random.nextInt(10)) {
            when (Random.nextInt(3)) {
                0 -> NameSegment(Base64.encode(Random.nextBytes(32)))
                1 -> IndexSegment(Random.nextUInt())
                else -> NullSegment
            }
        }
        val pointer = DCQLClaimsPathPointer(segments.toNonEmptyList())
        val jsonElement = buildJsonArray {
            segments.forEach {
                add(
                    when (it) {
                        is IndexSegment -> JsonPrimitive(it.index.toLong())
                        is NameSegment -> JsonPrimitive(it.name)
                        is NullSegment -> JsonNull
                    }
                )
            }
        }
        Json.encodeToJsonElement(pointer) shouldBe jsonElement
        Json.decodeFromJsonElement<DCQLClaimsPathPointer>(jsonElement) shouldBe pointer
    }
}