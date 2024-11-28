package at.asitplus.wallet.lib.data.rfc7519

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json

class NumericDateSerializationTest : FreeSpec({
    "simple tests" - {
        withData(
            data = mapOf(
                "epoch" to 0,
                "sometime in the future" to 9e15,
                "sometime in the past" to -9e15,
            )
        ) {
            val value = Json.decodeFromString<NumericDate>(it.toString())
            value.secondsSinceEpoch shouldBe it
        }
    }
})