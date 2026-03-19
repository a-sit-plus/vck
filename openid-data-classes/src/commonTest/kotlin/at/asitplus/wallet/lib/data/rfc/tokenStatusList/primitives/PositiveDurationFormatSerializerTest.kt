package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.wallet.lib.data.vckJsonSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

val PositiveDurationFormatSerializerTest by testSuite {
    "validation" - {
        withDataSuites(
            mapOf<String, Pair<List<Duration>, Boolean>>(
                "negative duration" to Pair(
                    listOf(
                        (-1).toDuration(DurationUnit.HOURS),
                        (-1).toDuration(DurationUnit.MINUTES),
                        (-1).toDuration(DurationUnit.SECONDS),
                    ),
                    false,
                ),
                "zero duration" to Pair(
                    listOf(Duration.ZERO),
                    false,
                ),
                "positive duration" to Pair(
                    listOf(
                        1.toDuration(DurationUnit.SECONDS),
                        1.toDuration(DurationUnit.MINUTES),
                        1.toDuration(DurationUnit.HOURS),
                    ),
                    true,
                ),
            ),
        ) { (durations, isValid) ->
            withData(durations) { duration ->
                runCatching { PositiveDuration(duration) }.isSuccess shouldBe isValid
            }
        }
    }

    "JSON serialization keeps ttl as a number" - {
        withData(
            mapOf(
                "whole seconds" to Pair(1.toDuration(DurationUnit.SECONDS), "1"),
                "minutes" to Pair(1.toDuration(DurationUnit.MINUTES), "60"),
                "hours" to Pair(1.toDuration(DurationUnit.HOURS), "3600"),
                "fractional seconds" to Pair(1.5.toDuration(DurationUnit.SECONDS), "1.5"),
            )
        ) { (duration, expectedJson) ->
            val value = PositiveDuration(duration)
            val encoded = vckJsonSerializer.encodeToString(PositiveDurationFormatSerializer, value)

            encoded shouldBe expectedJson
            vckJsonSerializer.decodeFromString(PositiveDurationFormatSerializer, encoded) shouldBe value
        }
    }

    "CBOR serialization round-trips whole-second ttl values" - {
        withData(
            mapOf(
                "1 second" to PositiveDuration(1.toDuration(DurationUnit.SECONDS)),
                "1 minute" to PositiveDuration(1.toDuration(DurationUnit.MINUTES)),
                "1 hour" to PositiveDuration(1.toDuration(DurationUnit.HOURS)),
            )
        ) { value ->
            val encoded = coseCompliantSerializer.encodeToByteArray(PositiveDurationFormatSerializer, value)

            coseCompliantSerializer.decodeFromByteArray(PositiveDurationFormatSerializer, encoded) shouldBe value
        }
    }
}
