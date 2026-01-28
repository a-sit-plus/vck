package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.extensions.toView
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToHexString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

@OptIn(ExperimentalSerializationApi::class)
val StatusListSerializationTest by testSuite {
    "json" - {
        "deserialization" - {
            withData(
                mapOf(
                    "one bit status codes" to Pair<String, List<TokenStatus>>(
                        """{
                          "bits": 1,
                          "lst": "eNrbuRgAAhcBXQ"
                        }""",
                        listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).map {
                            TokenStatus(it.toUInt())
                        }
                    ),
                    "two bit status codes" to Pair<String, List<TokenStatus>>(
                        """{
                          "bits": 2,
                          "lst": "eNrbuRgAAhcBXQ"
                        }""",
                        listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(2).map { bits ->
                            TokenStatus(
                                bits.reduceIndexed { index, acc, it ->
                                    acc + it.shl(index)
                                }.toUInt()
                            )
                        }
                    ),
                    "four bit status codes" to Pair<String, List<TokenStatus>>(
                        """{
                          "bits": 4,
                          "lst": "eNrbuRgAAhcBXQ"
                        }""",
                        listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(4).map { bits ->
                            TokenStatus(
                                bits.reduceIndexed { index, acc, it ->
                                    acc + it.shl(index)
                                }.toUInt()
                            )
                        }
                    ),
                    "eight bit status codes" to Pair<String, List<TokenStatus>>(
                        """{
                          "bits": 8,
                          "lst": "eNrbuRgAAhcBXQ"
                        }""",
                        listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(8).map { bits ->
                            TokenStatus(
                                bits.reduceIndexed { index, acc, it ->
                                    acc + it.shl(index)
                                }.toUInt()
                            )
                        }
                    ),
                    "invalid bits" to Pair(
                        """{
                          "bits": 3,
                          "lst": "eNrbuRgAAhcBXQ"
                        }""",
                        listOf()
                    ),
                    "invalid bits" to Pair(
                        """{
                          "bits": 2,
                          "lst": "eNo76fITAAPfAgc"
                        }""",
                        listOf(1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3).map {
                            TokenStatus(it.toUByte())
                        }
                    ),
                )
            ) { (jsonString, expectedStatusList) ->
                val jsonObject = Json.decodeFromString<JsonObject>(jsonString)
                val expectedBits = catchingUnwrapped {
                    TokenStatusBitSize.valueOf(jsonObject["bits"]!!.jsonPrimitive.long.toUInt())
                }.getOrNull()
                if (expectedBits == null) {
                    shouldThrowAny {
                        Json.decodeFromString<StatusList>(jsonString)
                    }
                } else {
                    val statusList = Json.decodeFromString<StatusList>(jsonString)

                    expectedStatusList.forEachIndexed { index, it ->
                        statusList.toView()[index.toULong()] shouldBe it
                    }

                    Json.decodeFromString<StatusList>(Json.encodeToString(statusList)) shouldBe statusList
                }
            }
        }
    }
    "cbor" - {
        withData(
            mapOf(
                "one bit status codes" to Pair<String, List<TokenStatus>>(
                    """a2646269747301636c73744a78dadbb918000217015d""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).map {
                        TokenStatus(it.toUInt())
                    }
                ),
                "two bit status codes" to Pair<String, List<TokenStatus>>(
                    """A2646269747302636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(2).map { bits ->
                        TokenStatus(
                            bits.reduceIndexed { index, acc, it ->
                                acc + it.shl(index)
                            }.toUInt()
                        )
                    }
                ),
                "four bit status codes" to Pair<String, List<TokenStatus>>(
                    """A2646269747304636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(4).map { bits ->
                        TokenStatus(
                            bits.reduceIndexed { index, acc, it ->
                                acc + it.shl(index)
                            }.toUInt()
                        )
                    }
                ),
                "eight bit status codes" to Pair<String, List<TokenStatus>>(
                    """A2646269747308636C73744A78DADBB918000217015D""",
                    listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1).chunked(8).map { bits ->
                        TokenStatus(
                            bits.reduceIndexed { index, acc, it ->
                                acc + it.shl(index)
                            }.toUInt()
                        )
                    }
                ),
            )
        ) { (cborString, expectedStatusList) ->
            val statusList = coseCompliantSerializer.decodeFromHexString<StatusList>(cborString)
            expectedStatusList.forEachIndexed { index, it ->
                statusList.toView()[index.toULong()] shouldBe it
            }

            coseCompliantSerializer.decodeFromHexString<StatusList>(coseCompliantSerializer.encodeToHexString(statusList)) shouldBe statusList
        }
    }
}