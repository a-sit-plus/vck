package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.random.Random
import kotlin.random.nextUInt

val DCQLClaimsPathPointerSegmentTest by testSuite {
    "select" - {
        "null" {
            val selection = DCQLClaimsPathPointerSegment.NullSegment.query(
                listOf(
                    NodeListEntry(
                        value = buildJsonArray {
                            add(JsonPrimitive(0))
                            add(JsonPrimitive(1))
                            add(JsonPrimitive(2))
                        },
                        normalizedJsonPath = NormalizedJsonPath()
                    )
                )
            )
            selection shouldHaveSize 3
            selection.forEach {
                it.normalizedJsonPath.segments shouldHaveSize 1
                val segment = it.normalizedJsonPath.segments.first()
                    .shouldBeInstanceOf<NormalizedJsonPathSegment.IndexSegment>()
                segment.index.toInt() shouldBe it.value.jsonPrimitive.long
            }
        }
        "string" - {
            val keys = listOf("0u", "1u", "2u")
            val nodeList = listOf(
                NodeListEntry(
                    value = buildJsonObject {
                        keys.forEach {
                            put(it, JsonNull)
                        }
                    },
                    normalizedJsonPath = NormalizedJsonPath()
                )
            )
            withData(keys) {
                val selection = DCQLClaimsPathPointerSegment.NameSegment(it)
                    .query(nodeList)
                selection shouldHaveSize 1
                selection.first().run {
                    normalizedJsonPath.segments shouldHaveSize 1
                    normalizedJsonPath.segments.first()
                        .shouldBeInstanceOf<NormalizedJsonPathSegment.NameSegment>()
                        .memberName shouldBe it
                    value shouldBe JsonNull
                }
            }
        }
        "index" - {
            val nodeList = listOf(
                NodeListEntry(
                    value = buildJsonArray {
                        add(JsonPrimitive(0))
                        add(JsonPrimitive(1))
                        add(JsonPrimitive(2))
                    },
                    normalizedJsonPath = NormalizedJsonPath()
                )
            )
            withData(
                listOf(0u, 1u, 2u)
            ) { index ->
                val selection = DCQLClaimsPathPointerSegment.IndexSegment(index)
                    .query(nodeList)
                selection shouldHaveSize 1
                selection.first().run {
                    normalizedJsonPath.segments shouldHaveSize 1
                    normalizedJsonPath.segments.first()
                        .shouldBeInstanceOf<NormalizedJsonPathSegment.IndexSegment>()
                        .index shouldBe index
                    value.jsonPrimitive.long shouldBe index.toLong()
                }
            }
        }
    }
    "serialization" - {
        val selection = DCQLClaimsPathPointerSegment.NullSegment.query(
            listOf(
                NodeListEntry(
                    value = buildJsonArray {
                        add(JsonNull)
                        add(JsonNull)
                        add(JsonNull)
                    },
                    normalizedJsonPath = NormalizedJsonPath()
                )
            )
        )
        selection shouldHaveSize 3

        withData(
            List(1 + Random.nextInt(10)) {
                when (Random.nextInt(3)) {
                    0 -> Random.nextBytes(32).encodeBase64()
                    1 -> Random.nextUInt()
                    else -> null
                }
            }
        ) {
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