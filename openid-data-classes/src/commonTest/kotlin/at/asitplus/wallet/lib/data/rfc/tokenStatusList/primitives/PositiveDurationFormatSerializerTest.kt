package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.wallet.lib.data.vckJsonSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.DurationUnit
import kotlin.time.toDuration
import kotlinx.serialization.SerializationException

val PositiveDurationFormatSerializerTest by testSuite {
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

    "JSON deserialization rejects non-positive ttl values" - {
        withData(
            mapOf(
                "zero" to "0",
                "negative whole seconds" to "-1",
                "negative fractional seconds" to "-1.5",
            )
        ) { encoded ->
            shouldThrow<SerializationException> {
                vckJsonSerializer.decodeFromString(PositiveDurationFormatSerializer, encoded)
            }
        }
    }

    "CBOR serialization uses unsigned integer values for whole-second ttl" - {
        withData(
            mapOf(
                "1 second" to Pair(PositiveDuration(1.toDuration(DurationUnit.SECONDS)), "01"),
                "1 minute" to Pair(PositiveDuration(1.toDuration(DurationUnit.MINUTES)), "183C"),
                "1 hour" to Pair(PositiveDuration(1.toDuration(DurationUnit.HOURS)), "190E10"),
            )
        ) { (value, expectedHex) ->
            val encoded = coseCompliantSerializer.encodeToByteArray(PositiveDurationFormatSerializer, value)

            encoded.encodeToString(Base16Strict).uppercase() shouldBe expectedHex
            coseCompliantSerializer.decodeFromByteArray(PositiveDurationFormatSerializer, encoded) shouldBe value
        }
    }

    "CBOR deserialization rejects unsupported ttl values" - {
        withData(
            mapOf(
                "zero" to "00",
                "negative one" to "20",
                "above Long.MAX_VALUE" to "1B8000000000000000",
            )
        ) { encodedHex ->
            shouldThrow<SerializationException> {
                coseCompliantSerializer.decodeFromByteArray(
                    PositiveDurationFormatSerializer,
                    encodedHex.decodeToByteArray(Base16Strict),
                )
            }
        }
    }
}
