package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive

class TimeToLiveSerializationTest : FreeSpec({
    "from draft" - {
        "json" - {
            withData(
                mapOf(
                    "43200" to JwtTimeToLive(PositiveJsonNumber(JsonPrimitive(43200.0))),
                    "43200.123" to JwtTimeToLive(PositiveJsonNumber(JsonPrimitive(43200.123))),
                    "432e2" to JwtTimeToLive(PositiveJsonNumber(JsonPrimitive(432e2))),
                )
            ) {
                Json.decodeFromString<TimeToLive>(testCase.name.testName).duration shouldBe it.duration
                Json.decodeFromString<JwtTimeToLive>(testCase.name.testName).duration shouldBe it.duration
            }
            withData(
                listOf(
                    "-43200",
                    "-43200.123",
                    "-432e2",
                )
            ) {
                shouldThrow<IllegalArgumentException> {
                    Json.decodeFromString<TimeToLive>(it)
                }
                shouldThrow<IllegalArgumentException> {
                    Json.decodeFromString<JwtTimeToLive>(it)
                }
            }
        }
        "cbor" - {
            withData(
                mapOf(
                    "43200" to CwtTimeToLive(43200u),
                )
            ) {
                Json.decodeFromString<TimeToLive>(testCase.name.testName).duration shouldBe it.duration
                Json.decodeFromString<CwtTimeToLive>(testCase.name.testName).duration shouldBe it.duration
            }
            withData(
                listOf(
                    "43200.123",
                    "-43200",
                    "-43200.123",
                    "-432e2",
                )
            ) {
                shouldThrow<IllegalArgumentException> {
                    Json.decodeFromString<CwtTimeToLive>(it)
                }
            }
        }
    }
})