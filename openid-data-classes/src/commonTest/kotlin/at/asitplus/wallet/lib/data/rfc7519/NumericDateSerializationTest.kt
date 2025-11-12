package at.asitplus.wallet.lib.data.rfc7519

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.time.Instant

val NumericDateSerializationTest by testSuite {
    "simple tests" - {
        withData(
           mapOf(
                "epoch" to 0,
                "sometime in the future" to Instant.Companion.DISTANT_FUTURE.epochSeconds,
                "sometime in the past" to Instant.Companion.DISTANT_PAST.epochSeconds,
            )
        ) {
            val value = Json.Default.decodeFromString<NumericDate>(it.toString())
            value.instant shouldBe Instant.Companion.fromEpochSeconds(it)
        }
    }
}