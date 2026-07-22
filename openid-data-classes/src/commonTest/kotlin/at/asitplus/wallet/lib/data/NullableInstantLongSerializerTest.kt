@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.time.Instant

private const val VALUE = "value"

@Serializable
private data class LegacySerializedInstant(
    @Serializable(with = NullableInstantLongSerializer::class)
    val value: Instant?,
)

@Serializable
private data class SignumSerializedInstant(
    @Serializable(with = InstantLongSerializer::class)
    val value: Instant?,
)

@Deprecated("To be removed with [NullableInstantLongSerializer]")
val NullableInstantLongSerializerTest by matrixSuite {
    "serialization is equivalent to Signum's InstantLongSerializer" - {
        mapOf(
            "null" to null,
            "Unix epoch" to Instant.fromEpochSeconds(0),
            "before Unix epoch" to Instant.fromEpochSeconds(-1),
            "fractional second" to Instant.fromEpochSeconds(1_721_234_567, 890_123_456),
        ).asData(nameFn = { (name, _) -> name }) test { (_, instant) ->
            Json.encodeToString(LegacySerializedInstant(instant)) shouldBe
                Json.encodeToString(SignumSerializedInstant(instant))
        }
    }

    "deserialization is equivalent to Signum's InstantLongSerializer" - {
        mapOf(
            "null" to "null",
            "Unix epoch" to "0",
            "before Unix epoch" to "-1",
            "positive epoch seconds" to "1721234567",
        ).asData(nameFn = { (name, _) -> name }) test { (_, encodedValue) ->
            val encoded = """{"$VALUE":$encodedValue}"""

            Json.decodeFromString<LegacySerializedInstant>(encoded).value shouldBe
                Json.decodeFromString<SignumSerializedInstant>(encoded).value
        }
    }
}
