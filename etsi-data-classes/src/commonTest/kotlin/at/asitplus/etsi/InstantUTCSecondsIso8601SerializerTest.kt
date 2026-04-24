package at.asitplus.etsi

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Instant

val EtsiInstantSerializerTest by testSuite{
    testSuite("deserialization success") {
        withData(
            mapOf(
                "2023-01-01T00:00:00Z" to Instant.fromEpochSeconds(1672531200),
                "2023-01-02T12:34:56Z" to Instant.fromEpochSeconds(1672662896),
                "2020-02-29T23:59:59Z" to Instant.fromEpochSeconds(1583020799),
                "1999-12-31T23:59:59Z" to Instant.fromEpochSeconds(946684799),
                "2000-01-01T00:00:00Z" to Instant.fromEpochSeconds(946684800),
                "2015-06-30T18:45:10Z" to Instant.fromEpochSeconds(1435689910),
                "2018-11-20T08:15:42Z" to Instant.fromEpochSeconds(1542701742),
                "2024-04-22T14:03:00Z" to Instant.fromEpochSeconds(1713794580),
                "2030-03-18T03:20:00Z" to Instant.fromEpochSeconds(1900034400),
                "1970-01-01T00:00:00Z" to Instant.fromEpochSeconds(0),
            ).mapValues {
                Json.encodeToString(it.key) to it.value
            }
        ) {(string, expected) ->
            Json.decodeFromString(
                EtsiInstantSerializer(),
                string
            ) shouldBe expected
        }
    }

    testSuite("deserialization failure because of second fractions") {
        withData(
            listOf(
                "2023-01-01T00:00:00.00Z",
                "2023-01-02T12:34:56.01Z",
            ).associateWith {
                Json.encodeToString(it)
            }
        ) {string ->
            shouldThrow<IllegalArgumentException> {
                Json.decodeFromString(
                    EtsiInstantSerializer(),
                    string
                )
            }
        }
    }

    testSuite("deserialization failure because of timezone") {
        withData(
            listOf(
                "2023-01-01T00:00:00.00",
                "2023-01-01T00:00:00.00+00:00",
                "2023-01-01T00:00:00.00+01:00",
                "2023-01-01T00:00:00.00+0100",
                "2023-01-01T00:00:00.00+01",
                "2023-01-01T00:00:00.00-04:30",
            ).associateWith {
                Json.encodeToString(it)
            }
        ) {string ->
            shouldThrow<IllegalArgumentException> {
                Json.decodeFromString(
                    EtsiInstantSerializer(),
                    string
                )
            }
        }
    }

    testSuite("serialization success") {
        withData(
            mapOf(
                "2023-01-01T00:00:00Z" to Instant.fromEpochSeconds(1672531200),
                "2023-01-02T12:34:56Z" to Instant.fromEpochSeconds(1672662896),
                "2020-02-29T23:59:59Z" to Instant.fromEpochSeconds(1583020799),
                "1999-12-31T23:59:59Z" to Instant.fromEpochSeconds(946684799),
                "2000-01-01T00:00:00Z" to Instant.fromEpochSeconds(946684800),
                "2015-06-30T18:45:10Z" to Instant.fromEpochSeconds(1435689910),
                "2018-11-20T08:15:42Z" to Instant.fromEpochSeconds(1542701742),
                "2024-04-22T14:03:00Z" to Instant.fromEpochSeconds(1713794580),
                "2030-03-18T03:20:00Z" to Instant.fromEpochSeconds(1900034400),
                "1970-01-01T00:00:00Z" to Instant.fromEpochSeconds(0),
            ).mapValues {
                it.value to Json.encodeToString(it.key)
            }
        ) {(instant, expected) ->
            Json.encodeToString(
                EtsiInstantSerializer(),
                instant
            ) shouldBe expected
        }
    }

    testSuite("serialization failure because of second fractions") {
        withData(
            listOf(
                Instant.fromEpochSeconds(1672531200) + 1.nanoseconds,
            ).associateBy {
                it.toString()
            }
        ) {instant ->
            shouldThrow<IllegalArgumentException> {
                Json.encodeToString(
                    EtsiInstantSerializer(),
                    instant
                )
            }
        }
    }
}