package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.cosef.CborWebToken
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class TimeToLiveSerializationTest : FreeSpec({
    "from draft" - {
        "json" - {
            withData(
                mapOf(
                    "43200" to JwtTimeToLive(PositiveDuration(43200.0.toDuration(DurationUnit.SECONDS))),
                    "43200.123" to JwtTimeToLive(PositiveDuration(43200.123.toDuration(DurationUnit.SECONDS))),
                    "432e2" to JwtTimeToLive(PositiveDuration(43200.toDuration(DurationUnit.SECONDS))),
                )
            ) {
                Json.decodeFromString<TimeToLive>(testCase.name.testName) shouldBe it
                Json.decodeFromString<JwtTimeToLive>(testCase.name.testName) shouldBe it
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
    }
})