package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
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
 */
@Serializable
@JvmInline
value class NumericDate(
    // TODO: Replace with serializer that properly supports second fractions
    @Serializable(with = InstantLongSerializer::class)
    val instant: Instant,
)