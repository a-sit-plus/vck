package at.asitplus.wallet.lib.data.rfc7519.primitives

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.jvm.JvmInline

/**
 * A JSON numeric value representing the number of seconds from
 *       1970-01-01T00:00:00Z UTC until the specified UTC date/time,
 *       ignoring leap seconds.  This is equivalent to the IEEE Std 1003.1,
 *       2013 Edition [POSIX.1] definition "Seconds Since the Epoch", in
 *       which each day is accounted for by exactly 86400 seconds, other
 *       than that non-integer values can be represented.  See RFC 3339
 *       [RFC3339] for details regarding date/times in general and UTC in
 *       particular.
 *
 *  Note: Double has a precision of 53 bits.
 *  This is sufficient to represent more than 250000 years on millisecond precision.
 *  This is good enough for now, even for
 */
@Serializable(with = NumericDateInlineSerializer::class)
@JvmInline value class NumericDate(val secondsSinceEpoch: Double) {
    fun toInstant() = Instant.fromEpochMilliseconds((secondsSinceEpoch * 1000).toLong())

    companion object {
        fun fromInstant(instant: Instant) = NumericDate(
            secondsSinceEpoch = instant.toEpochMilliseconds().toDouble() / 1000
        )
    }
}