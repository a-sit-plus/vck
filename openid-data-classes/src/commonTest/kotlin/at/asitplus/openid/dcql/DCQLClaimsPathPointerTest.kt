package at.asitplus.openid.dcql

import at.asitplus.data.collections.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.collections.NonEmptyList.Companion.toNonEmptyList
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.encodeBase64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random
import kotlin.random.nextUInt

class DCQLClaimsPathPointerTest : FreeSpec({
    "constructors" - {
        withData(
            listOf("test", 0u, null)
        ) {
            when (it) {
                null -> DCQLClaimsPathPointer(it)
                is String -> DCQLClaimsPathPointer(it)
                else -> DCQLClaimsPathPointer(it as UInt)
            }.run {
                segments shouldHaveSize 1
                segments.first().run {
                    when (it) {
                        null -> {
                            shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NullSegment>()
                        }

                        is String -> {
                            shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
                            name shouldBe it
                        }

                        else -> {
                            shouldBeInstanceOf<DCQLClaimsPathPointerSegment.IndexSegment>()
                            index shouldBe it
                        }
                    }
                }
            }
        }
        withData(
            listOf(0u, 100u, UInt.MAX_VALUE)
        ) {
            DCQLClaimsPathPointer(it).run {
                segments shouldHaveSize 1
                segments.first().run {
                    shouldBeInstanceOf<DCQLClaimsPathPointerSegment.IndexSegment>()
                    index shouldBe it
                }
            }
        }
    }
    "concatenation conformance" - {
        "base" {
            val segments = List(1 + Random.nextInt(10)) {
                when (Random.nextInt(3)) {
                    0 -> DCQLClaimsPathPointerSegment.NameSegment(
                        Random.nextBytes(32).encodeBase64()
                    )

                    1 -> DCQLClaimsPathPointerSegment.IndexSegment(Random.nextUInt())
                    else -> DCQLClaimsPathPointerSegment.NullSegment
                }
            }
            DCQLClaimsPathPointer(segments.toNonEmptyList()) shouldBe segments.map {
                DCQLClaimsPathPointer(nonEmptyListOf(it))
            }.reduce { acc, it -> acc + it }
        }
        "values" {
            val segments = List(1 + Random.nextInt(10)) {
                when (Random.nextInt(3)) {
                    0 -> Random.nextBytes(32).encodeBase64()
                    1 -> Random.nextUInt()
                    else -> null
                }
            }

            DCQLClaimsPathPointer(segments.map {
                when (it) {
                    is String -> DCQLClaimsPathPointerSegment.NameSegment(it)
                    is UInt -> DCQLClaimsPathPointerSegment.IndexSegment(it)
                    else -> DCQLClaimsPathPointerSegment.NullSegment
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
                0 -> DCQLClaimsPathPointerSegment.NameSegment(
                    Random.nextBytes(32).encodeBase64()
                )

                1 -> DCQLClaimsPathPointerSegment.IndexSegment(Random.nextUInt())
                else -> DCQLClaimsPathPointerSegment.NullSegment
            }
        }
        val pointer = DCQLClaimsPathPointer(segments.toNonEmptyList())
        val jsonElement = buildJsonArray {
            segments.forEach {
                add(
                    when (it) {
                        is DCQLClaimsPathPointerSegment.IndexSegment -> {
                            JsonPrimitive(it.index.toLong())
                        }

                        is DCQLClaimsPathPointerSegment.NameSegment -> {
                            JsonPrimitive(it.name)
                        }

                        is DCQLClaimsPathPointerSegment.NullSegment -> JsonNull
                    }
                )
            }
        }
        Json.encodeToJsonElement(pointer) shouldBe jsonElement
        Json.decodeFromJsonElement<DCQLClaimsPathPointer>(jsonElement) shouldBe pointer
    }
})