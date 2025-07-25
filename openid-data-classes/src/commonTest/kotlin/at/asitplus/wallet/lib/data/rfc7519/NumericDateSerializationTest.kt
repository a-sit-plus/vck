package at.asitplus.wallet.lib.data.rfc7519

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Instant
import kotlinx.serialization.json.Json

class NumericDateSerializationTest : FreeSpec({
    "simple tests" - {
        withData(
            data = mapOf(
                "epoch" to 0,
                "sometime in the future" to Instant.Companion.DISTANT_FUTURE.epochSeconds,
                "sometime in the past" to Instant.Companion.DISTANT_PAST.epochSeconds,
            )
        ) {
            val value = Json.Default.decodeFromString<NumericDate>(it.toString())
            value.instant shouldBe Instant.Companion.fromEpochSeconds(it)
        }
    }
})