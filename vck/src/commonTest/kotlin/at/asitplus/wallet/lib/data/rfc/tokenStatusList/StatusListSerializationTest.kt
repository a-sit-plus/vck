package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.extensions.toView
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToHexString
import kotlinx.serialization.json.Json

@OptIn(ExperimentalSerializationApi::class)
val StatusListSerializationTest by testSuite {
    "json" - {
        withData(
            mapOf(
                "one bit status codes" to Pair(
                    """{ "bits": 1, "lst": "eNrbuRgAAhcBXQ" }""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(1)
                ),
                "two bit status codes" to Pair(
                    """{ "bits": 2, "lst": "eNrbuRgAAhcBXQ" }""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(2)
                ),
                "four bit status codes" to Pair(
                    """{ "bits": 4, "lst": "eNrbuRgAAhcBXQ" }""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(4)
                ),
                "eight bit status codes" to Pair(
                    """{ "bits": 8, "lst": "eNrbuRgAAhcBXQ" }""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(8)
                ),
            )
        ) { (jsonString, expectedStatusList) ->
            val statusList = Json.decodeFromString<StatusList>(jsonString)

            expectedStatusList.forEachIndexed { index, status ->
                statusList.toView()[index.toULong()] shouldBe status
            }

            val encoded = Json.encodeToString(statusList).apply {
                shouldContain("eNrbuRgAAhcBXQ")
            }
            Json.decodeFromString<StatusList>(encoded) shouldBe statusList
        }
    }
    "invalid json bits" {
        shouldThrowAny {
            Json.decodeFromString<StatusList>("""{ "bits": 3, "lst": "eNrbuRgAAhcBXQ" }""")
        }
    }
    "also valid json" {
        val jsonString = """{ "bits": 2, "lst": "eNo76fITAAPfAgc" }"""
        val expectedStatusList = listOf(1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3).toChunkedTokenStatus(1)
        val statusList = Json.decodeFromString<StatusList>(jsonString)

        expectedStatusList.forEachIndexed { index, status ->
            statusList.toView()[index.toULong()] shouldBe status
        }

        val encoded = Json.encodeToString(statusList)
        Json.decodeFromString<StatusList>(encoded) shouldBe statusList
    }
    "cbor" - {
        withData(
            mapOf(
                "one bit status codes" to Pair(
                    """a2646269747301636c73744a78dadbb918000217015d""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(1)
                ),
                "two bit status codes" to Pair(
                    """A2646269747302636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(2)
                ),
                "four bit status codes" to Pair(
                    """A2646269747304636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(4)
                ),
                "eight bit status codes" to Pair(
                    """A2646269747308636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).toChunkedTokenStatus(8)
                ),
            )
        ) { (cborString, expectedStatusList) ->
            val statusList = coseCompliantSerializer.decodeFromHexString<StatusList>(cborString)
            expectedStatusList.forEachIndexed { index, status ->
                statusList.toView()[index.toULong()] shouldBe status
            }

            val encoded = coseCompliantSerializer.encodeToHexString(statusList).apply {
                shouldContain("78dadbb918000217015d") // the encoded list only
            }

            coseCompliantSerializer.decodeFromHexString<StatusList>(encoded) shouldBe statusList
        }
    }
}

private fun List<Int>.toChunkedTokenStatus(chunkSize: Int) = chunked(chunkSize).map { bits ->
    TokenStatus(
        bits.reduceIndexed { index, acc, bit ->
            acc + bit.shl(index)
        }.toUInt()
    )
}