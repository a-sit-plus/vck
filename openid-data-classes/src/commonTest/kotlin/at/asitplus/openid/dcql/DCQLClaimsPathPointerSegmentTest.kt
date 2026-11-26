package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.random.nextUInt

val DCQLClaimsPathPointerSegmentTest by matrixSuite {
    "select" - {
        val array = buildJsonArray {
            add(JsonPrimitive(0))
            add(JsonPrimitive(1))
            add(JsonPrimitive(2))
        }
        "null selects each element at its index" {
            val selection = DCQLClaimsPathPointer(null).query(array)
            selection shouldHaveSize 3
            selection.forEach {
                it.path shouldBe DCQLClaimsPathPointer(it.value.jsonPrimitive.long.toUInt())
            }
        }
        "string" - {
            val keys = listOf("0u", "1u", "2u")
            val credential = buildJsonObject {
                keys.forEach {
                    put(it, JsonNull)
                }
            }
            data(keys) test {
                DCQLClaimsPathPointer(it).query(credential).single() shouldBe
                        DCQLSelectedClaim(DCQLClaimsPathPointer(it), JsonNull)
            }
        }
        "index" - {
            listOf(0u, 1u, 2u).asData() test { index ->
                DCQLClaimsPathPointer(index).query(array).single() shouldBe
                        DCQLSelectedClaim(DCQLClaimsPathPointer(index), JsonPrimitive(index.toLong()))
            }
        }
    }
    "serialization" - {
        data(List(1 + Random.nextInt(10)) {
            when (Random.nextInt(3)) {
                0 -> Base64.encode(Random.nextBytes(32))
                1 -> Random.nextUInt()
                else -> null
            }
        }) test {
            val segment = when (it) {
                null -> DCQLClaimsPathPointerSegment.NullSegment
                is String -> DCQLClaimsPathPointerSegment.NameSegment(it)
                is UInt -> DCQLClaimsPathPointerSegment.IndexSegment(it)
                else -> throw IllegalStateException("Unexpected value type")
            }

            Json.encodeToJsonElement(segment) shouldBe when (it) {
                is String -> JsonPrimitive(it)
                is UInt -> JsonPrimitive(it.toLong())
                null -> JsonNull
                else -> throw IllegalStateException("Unexpected value type")
            }
        }
    }
}
